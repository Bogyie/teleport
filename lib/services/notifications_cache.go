/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"

	notificationsv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/notifications/v1"
	"github.com/gravitational/teleport/api/internalutils/stream"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/sortcache"
)

const (
	// notificationKey is the key for a user-specific notification in the format of <username>/<notification uuid>.
	// This index is only used by the user notifications cache. Since UUIDv7's contain a timestamp and are lexicographically sortable
	// by date, this is what will be used to sort by date.
	notificationKey = "Key"
	// notificationID is the uuid of a notification.
	notificationID = "ID"
)

// NotificationGetter defines the interface for fetching notifications.
type NotificationGetter interface {
	// GetAllUserNotifications returns all user-specific notifications for all users.
	GetAllUserNotifications(ctx context.Context) ([]*notificationsv1.Notification, error)
	// GetAllGlobalNotifications returns all global notifications.
	GetAllGlobalNotifications(ctx context.Context) ([]*notificationsv1.GlobalNotification, error)
}

// UserNotificationsCacheConfig holds the configuration parameters for both [UserNotificationCache] and [GlobalNotificationCache].
type NotificationCacheConfig struct {
	// Clock is a clock for time-related operation.
	Clock clockwork.Clock
	// Events is an event system client.
	Events types.Events
	// Getter is an notification getter client.
	Getter NotificationGetter
}

// CheckAndSetDefaults validates the config and provides reasonable defaults for optional fields.
func (c *NotificationCacheConfig) CheckAndSetDefaults() error {
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}

	if c.Events == nil {
		return trace.BadParameter("notification cache config missing event system client")
	}

	if c.Getter == nil {
		return trace.BadParameter("notification cache config missing notifications getter")
	}

	return nil
}

// UserNotificationCache is a custom cache for user-specific notifications, this is to allow
// fetching notifications by date in descending order.
type UserNotificationCache struct {
	rw           sync.RWMutex
	cfg          NotificationCacheConfig
	primaryCache *sortcache.SortCache[*notificationsv1.Notification]
	ttlCache     *utils.FnCache
	initC        chan struct{}
	closeContext context.Context
	cancel       context.CancelFunc
}

// GlobalNotificationCache is a custom cache for user-specific notifications, this is to allow
// fetching notifications by date in descending order.
type GlobalNotificationCache struct {
	rw           sync.RWMutex
	cfg          NotificationCacheConfig
	primaryCache *sortcache.SortCache[*notificationsv1.GlobalNotification]
	ttlCache     *utils.FnCache
	initC        chan struct{}
	closeContext context.Context
	cancel       context.CancelFunc
}

// NewUserNotificationCache sets up a new [UserNotificationCache] instance based on the supplied
// configuration. The cache is initialized asychronously in the background, so while it is
// safe to read from it immediately, performance is better after the cache properly initializes.
func NewUserNotificationCache(cfg NotificationCacheConfig) (*UserNotificationCache, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	ttlCache, err := utils.NewFnCache(utils.FnCacheConfig{
		Context: ctx,
		TTL:     15 * time.Second,
		Clock:   cfg.Clock,
	})
	if err != nil {
		cancel()
		return nil, trace.Wrap(err)
	}

	c := &UserNotificationCache{
		cfg:          cfg,
		ttlCache:     ttlCache,
		initC:        make(chan struct{}),
		closeContext: ctx,
		cancel:       cancel,
	}

	if _, err := newResourceWatcher(ctx, c, ResourceWatcherConfig{
		Component: "user-notification-cache",
		Client:    cfg.Events,
	}); err != nil {
		cancel()
		return nil, trace.Wrap(err)
	}

	return c, nil
}

// NewGlobalNotificationCache sets up a new [GlobalNotificationCache] instance based on the supplied
// configuration. The cache is initialized asychronously in the background, so while it is
// safe to read from it immediately, performance is better after the cache properly initializes.
func NewGlobalNotificationCache(cfg NotificationCacheConfig) (*GlobalNotificationCache, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	ttlCache, err := utils.NewFnCache(utils.FnCacheConfig{
		Context: ctx,
		TTL:     15 * time.Second,
		Clock:   cfg.Clock,
	})
	if err != nil {
		cancel()
		return nil, trace.Wrap(err)
	}

	c := &GlobalNotificationCache{
		cfg:          cfg,
		ttlCache:     ttlCache,
		initC:        make(chan struct{}),
		closeContext: ctx,
		cancel:       cancel,
	}

	if _, err := newResourceWatcher(ctx, c, ResourceWatcherConfig{
		Component: "global-notification-cache",
		Client:    cfg.Events,
	}); err != nil {
		cancel()
		return nil, trace.Wrap(err)
	}

	return c, nil
}

// streamUserNotifications returns a stream with the user-specific notifications in the cache for a specified user sorted from newest to oldest.
// We use streams here as it's a convenient way for us to construct pages to be returned to the UI one item at a time in combination with global notifications.
func (c *UserNotificationCache) StreamUserNotifications(ctx context.Context, username string, startKey string) stream.Stream[*notificationsv1.Notification] {
	if username == "" {
		return stream.Fail[*notificationsv1.Notification](trace.BadParameter("username is required for fetching user notifications"))
	}

	cache, err := c.read(ctx)
	if err != nil {
		return stream.Fail[*notificationsv1.Notification](trace.Wrap(err))
	}

	if !cache.HasIndex(notificationKey) {
		return stream.Fail[*notificationsv1.Notification](trace.Errorf("user notifications cache was not configured with index %q (this is a bug)", notificationKey))
	}

	if startKey == "" {
		// If the startKey isn't specified, we get the initial startKey by descending through the user notifications cache until we get the first notification
		// for this user's username.
		cache.Descend(notificationKey, "", "", func(notification *notificationsv1.Notification) bool {
			// If this notification is for the user, we set the startKey to it and exit the traversal.
			if notification.GetSpec().GetUsername() == username {
				startKey = GetUserSpecificKey(notification)
				// Exit traversal.
				return false
			}

			return true
		})
	}

	notifications := []*notificationsv1.Notification{}

	// We get all the user-specific notifications for this user from the cache up-front, starting with the startKey.
	cache.Descend(notificationKey, startKey, "", func(n *notificationsv1.Notification) bool {
		// Once we reach notifications that belong to a different user, it means that this user has no more user-specific notifications and we stop traversing.
		if n.GetSpec().GetUsername() != username {
			return false
		}

		notifications = append(notifications, n)
		return true
	})

	return stream.Slice(notifications)
}

// fetch initializes a sortcache with all existing user-specific notifications. This is used to set up the initialize the primary cache, and
// to create a temporary cache as a fallback in case the primary cache is ever unhealthy.
func (c *UserNotificationCache) fetch(ctx context.Context) (*sortcache.SortCache[*notificationsv1.Notification], error) {
	cache := sortcache.New(sortcache.Config[*notificationsv1.Notification]{
		Indexes: map[string]func(*notificationsv1.Notification) string{
			notificationKey: func(n *notificationsv1.Notification) string {
				return GetUserSpecificKey(n)
			},
			notificationID: func(n *notificationsv1.Notification) string {
				return n.GetMetadata().GetName()
			},
		},
	})

	// Get all user notifications for all users.
	notifications, err := c.cfg.Getter.GetAllUserNotifications(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, n := range notifications {
		if evicted := cache.Put(n); evicted != 0 {
			// this warning, if it appears, means that we configured our indexes incorrectly and one notification is overwriting another.
			// the most likely explanation is that one of our indexes is missing the notification id suffix we typically use.
			log.Warnf("Notification %q conflicted with %d other notifications during cache fetch. This is a bug and may result in notifications not appearing the in UI correctly.", n.GetMetadata().GetName(), evicted)
		}
	}

	return cache, nil
}

// GetUserSpecificKey returns the key for a user-specific notification in <username>/<notification uuid> format.
func GetUserSpecificKey(n *notificationsv1.Notification) string {
	username := n.GetSpec().GetUsername()
	id := n.GetSpec().GetId()

	return fmt.Sprintf("%s/%s", username, id)
}

// read gets a read-only view into a valid cache state. it prefers reading from the primary cache, but will fallback
// to a periodically reloaded temporary state when the primary state is unhealthy.
func (c *UserNotificationCache) read(ctx context.Context) (*sortcache.SortCache[*notificationsv1.Notification], error) {
	c.rw.RLock()
	primary := c.primaryCache
	c.rw.RUnlock()

	// primary cache state is healthy, so use that. note that we don't protect access to the sortcache itself
	// via our rw lock. sortcaches have their own internal locking.  we just use our lock to protect the *pointer*
	// to the sortcache.
	if primary != nil {
		return primary, nil
	}

	temp, err := utils.FnCacheGet(ctx, c.ttlCache, "user-notification-cache", func(ctx context.Context) (*sortcache.SortCache[*notificationsv1.Notification], error) {
		return c.fetch(ctx)
	})

	// primary may have been concurrently loaded. if it was, prefer using that.
	c.rw.RLock()
	primary = c.primaryCache
	c.rw.RUnlock()

	if primary != nil {
		return primary, nil
	}

	return temp, trace.Wrap(err)
}

// streamGlobalNotifications returns a stream with all the global notifications in the cache sorted by newest to oldest.
func (c *GlobalNotificationCache) StreamGlobalNotifications(ctx context.Context, startKey string) stream.Stream[*notificationsv1.GlobalNotification] {
	cache, err := c.read(ctx)
	if err != nil {
		return stream.Fail[*notificationsv1.GlobalNotification](trace.Wrap(err))
	}

	if !cache.HasIndex(notificationID) {
		return stream.Fail[*notificationsv1.GlobalNotification](trace.Errorf("global notifications cache was not configured with index %q (this is a bug)", notificationID))
	}

	globalNotifications := []*notificationsv1.GlobalNotification{}
	cache.Descend(notificationID, startKey, "", func(gn *notificationsv1.GlobalNotification) bool {
		globalNotifications = append(globalNotifications, gn)
		return true
	})

	return stream.Slice(globalNotifications)
}

// fetch initializes a sortcache with all existing global notifications. This is used to set up the initialize the primary cache, and
// to create a temporary cache as a fallback in case the primary cache is ever unhealthy.
func (c *GlobalNotificationCache) fetch(ctx context.Context) (*sortcache.SortCache[*notificationsv1.GlobalNotification], error) {
	cache := sortcache.New(sortcache.Config[*notificationsv1.GlobalNotification]{
		Indexes: map[string]func(*notificationsv1.GlobalNotification) string{
			notificationID: func(gn *notificationsv1.GlobalNotification) string {
				return gn.GetMetadata().GetName()
			},
		},
	})

	notifications, err := c.cfg.Getter.GetAllGlobalNotifications(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, n := range notifications {
		if evicted := cache.Put(n); evicted != 0 {
			// this warning, if it appears, means that we configured our indexes incorrectly and one notification is overwriting another.
			// the most likely explanation is that one of our indexes is missing the notification id suffix we typically use.
			log.Warnf("Notification %q conflicted with %d other notifications during cache fetch. This is a bug and may result in notifications not appearing the in UI correctly.", n.GetMetadata().GetName(), evicted)
		}
	}

	return cache, nil
}

// read gets a read-only view into a valid cache state. it prefers reading from the primary cache, but will fallback
// to a periodically reloaded temporary state when the primary state is unhealthy.
func (c *GlobalNotificationCache) read(ctx context.Context) (*sortcache.SortCache[*notificationsv1.GlobalNotification], error) {
	c.rw.RLock()
	primary := c.primaryCache
	c.rw.RUnlock()

	// primary cache state is healthy, so use that. note that we don't protect access to the sortcache itself
	// via our rw lock. sortcaches have their own internal locking.  we just use our lock to protect the *pointer*
	// to the sortcache.
	if primary != nil {
		return primary, nil
	}

	temp, err := utils.FnCacheGet(ctx, c.ttlCache, "global-notification-cache", func(ctx context.Context) (*sortcache.SortCache[*notificationsv1.GlobalNotification], error) {
		return c.fetch(ctx)
	})

	// primary may have been concurrently loaded. if it was, prefer using that.
	c.rw.RLock()
	primary = c.primaryCache
	c.rw.RUnlock()

	if primary != nil {
		return primary, nil
	}

	return temp, trace.Wrap(err)
}

// --- the below methods implement the resourceCollector interface ---

// resourceKinds is part of the resourceCollector interface and is used to configure the event watcher
// that monitors for notification modifications.
func (c *UserNotificationCache) resourceKinds() []types.WatchKind {
	return []types.WatchKind{
		{
			Kind: types.KindNotification,
		},
	}
}
func (c *GlobalNotificationCache) resourceKinds() []types.WatchKind {
	return []types.WatchKind{
		{
			Kind: types.KindGlobalNotification,
		},
	}
}

// getResourcesAndUpdateCurrent is part of the resourceCollector interface and is called when the
// event stream for the cache has been initialized to trigger setup of the initial primary cache state.
func (c *UserNotificationCache) getResourcesAndUpdateCurrent(ctx context.Context) error {
	cache, err := c.fetch(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	c.rw.Lock()
	defer c.rw.Unlock()
	c.primaryCache = cache
	return nil
}
func (c *GlobalNotificationCache) getResourcesAndUpdateCurrent(ctx context.Context) error {
	cache, err := c.fetch(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	c.rw.Lock()
	defer c.rw.Unlock()
	c.primaryCache = cache
	return nil
}

// processEventAndUpdateCurrent is part of the resourceCollector interface and is used to update the
// primary cache state when modification events occur.
func (c *UserNotificationCache) processEventAndUpdateCurrent(ctx context.Context, event types.Event) {
	c.rw.RLock()
	cache := c.primaryCache
	c.rw.RUnlock()
	switch event.Type {
	case types.OpPut:
		// Since the EventsService watcher currently only supports legacy resources, we had to use types.Resource153ToLegacy() when parsing the event
		// to transform the notification into a legacy resource. We now have to use Unwrap() to get the original RFD153-style notification out and add it to the cache.
		resource153 := event.Resource.(interface{ Unwrap() types.Resource153 }).Unwrap()
		notification, ok := resource153.(*notificationsv1.Notification)
		if !ok {
			log.Warnf("Unexpected resource type %T in event (expected %T)", resource153, notification)
			return
		}
		if evicted := cache.Put(notification); evicted > 1 {
			log.Warnf("Processing of put event for notification %q resulted in multiple cache evictions (this is a bug).", notification.GetMetadata().GetName())
		}
	case types.OpDelete:
		cache.Delete(notificationID, event.Resource.GetName())
	default:
		log.Warnf("Unexpected event variant: %+v", event)
	}
}
func (c *GlobalNotificationCache) processEventAndUpdateCurrent(ctx context.Context, event types.Event) {
	c.rw.RLock()
	cache := c.primaryCache
	c.rw.RUnlock()
	switch event.Type {
	case types.OpPut:
		resource153 := event.Resource.(interface{ Unwrap() types.Resource153 }).Unwrap()
		globalNotification, ok := resource153.(*notificationsv1.GlobalNotification)
		if !ok {
			log.Warnf("Unexpected resource type %T in event (expected %T)", resource153, globalNotification)
			return
		}
		if evicted := cache.Put(globalNotification); evicted > 1 {
			log.Warnf("Processing of put event for notification %q resulted in multiple cache evictions (this is a bug).", globalNotification.GetMetadata().GetName())
		}
	case types.OpDelete:
		cache.Delete(notificationID, event.Resource.GetName())
	default:
		log.Warnf("Unexpected event variant: %+v", event)
	}
}

// notifyStale is part of the resourceCollector interface and is used to inform
// the notification cache that its view is outdated (presumably due to issues with
// the event stream).
func (c *UserNotificationCache) notifyStale() {
	c.rw.Lock()
	defer c.rw.Unlock()
	if c.primaryCache == nil {
		return
	}
	c.primaryCache = nil
	c.initC = make(chan struct{})
}
func (c *GlobalNotificationCache) notifyStale() {
	c.rw.Lock()
	defer c.rw.Unlock()
	if c.primaryCache == nil {
		return
	}
	c.primaryCache = nil
	c.initC = make(chan struct{})
}

// initializationChan is part of the resourceCollector interface and gets the channel
// used to signal that the notification cache has been initialized.
func (c *UserNotificationCache) initializationChan() <-chan struct{} {
	c.rw.RLock()
	defer c.rw.RUnlock()
	return c.initC
}
func (c *GlobalNotificationCache) initializationChan() <-chan struct{} {
	c.rw.RLock()
	defer c.rw.RUnlock()
	return c.initC
}

// Close terminates the background process that keeps the notification cache up to
// date, and terminates any inflight load operations.
func (c *UserNotificationCache) Close() error {
	c.cancel()
	return nil
}
func (c *GlobalNotificationCache) Close() error {
	c.cancel()
	return nil
}
