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

package discovery

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/timestamppb"

	discoveryconfigv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/discoveryconfig/v1"
	usertasksv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/usertasks/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/discoveryconfig"
	"github.com/gravitational/teleport/api/types/usertasks"
	"github.com/gravitational/teleport/api/utils/retryutils"
	libevents "github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	aws_sync "github.com/gravitational/teleport/lib/srv/discovery/fetchers/aws-sync"
	"github.com/gravitational/teleport/lib/srv/server"
)

// updateDiscoveryConfigStatus updates the DiscoveryConfig Status field with the current in-memory status.
// The status will be updated with the following matchers:
// - AWS Sync (TAG) status
// - AWS EC2 Auto Discover status
// - AWS RDS Auto Discover status
// - AWS EKS Auto Discover status
func (s *Server) updateDiscoveryConfigStatus(discoveryConfigNames ...string) {
	for _, discoveryConfigName := range discoveryConfigNames {
		// Static configurations (ie those in `teleport.yaml/discovery_config.<cloud>.matchers`) do not have a DiscoveryConfig resource.
		// Those are discarded because there's no Status to update.
		if discoveryConfigName == "" {
			return
		}

		discoveryConfigStatus := discoveryconfig.Status{
			State:                          discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_SYNCING.String(),
			LastSyncTime:                   s.clock.Now(),
			IntegrationDiscoveredResources: make(map[string]*discoveryconfigv1.IntegrationDiscoveredSummary),
		}

		// Merge AWS Sync (TAG) status
		discoveryConfigStatus = s.awsSyncStatus.mergeIntoGlobalStatus(discoveryConfigName, discoveryConfigStatus)

		// Merge AWS EC2 Instances (auto discovery) status
		discoveryConfigStatus = s.awsEC2ResourcesStatus.mergeIntoGlobalStatus(discoveryConfigName, discoveryConfigStatus)

		// Merge AWS RDS databases (auto discovery) status
		discoveryConfigStatus = s.awsRDSResourcesStatus.mergeIntoGlobalStatus(discoveryConfigName, discoveryConfigStatus)

		// Merge AWS EKS clusters (auto discovery) status
		discoveryConfigStatus = s.awsEKSResourcesStatus.mergeIntoGlobalStatus(discoveryConfigName, discoveryConfigStatus)

		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()

		_, err := s.AccessPoint.UpdateDiscoveryConfigStatus(ctx, discoveryConfigName, discoveryConfigStatus)
		switch {
		case trace.IsNotImplemented(err):
			s.Log.WarnContext(ctx, "UpdateDiscoveryConfigStatus method is not implemented in Auth Server. Please upgrade it to a recent version.")
		case err != nil:
			s.Log.InfoContext(ctx, "Error updating discovery config status", "discovery_config_name", discoveryConfigName, "error", err)
		}
	}
}

// awsSyncStatus contains all the status for aws_sync Fetchers grouped by DiscoveryConfig.
type awsSyncStatus struct {
	mu sync.RWMutex
	// awsSyncResults maps the DiscoveryConfig name to a aws_sync result.
	// Each DiscoveryConfig might have multiple `aws_sync` matchers.
	awsSyncResults map[string][]awsSyncResult
}

// awsSyncResult stores the result of the aws_sync Matchers for a given DiscoveryConfig.
type awsSyncResult struct {
	// state is the State for the DiscoveryConfigStatus.
	// Allowed values are:
	// - DISCOVERY_CONFIG_STATE_SYNCING
	// - DISCOVERY_CONFIG_STATE_ERROR
	// - DISCOVERY_CONFIG_STATE_RUNNING
	state               string
	errorMessage        *string
	lastSyncTime        time.Time
	discoveredResources uint64
}

func (d *awsSyncStatus) iterationFinished(fetchers []aws_sync.AWSSync, pushErr error, lastUpdate time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.awsSyncResults = make(map[string][]awsSyncResult)
	for _, fetcher := range fetchers {
		// Only update the status for fetchers that are from the discovery config.
		if !fetcher.IsFromDiscoveryConfig() {
			continue
		}

		count, statusErr := fetcher.Status()
		statusAndPushErr := trace.NewAggregate(statusErr, pushErr)

		fetcherResult := awsSyncResult{
			state:               discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_RUNNING.String(),
			lastSyncTime:        lastUpdate,
			discoveredResources: count,
		}

		if statusAndPushErr != nil {
			errorMessage := statusAndPushErr.Error()
			fetcherResult.errorMessage = &errorMessage
			fetcherResult.state = discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_ERROR.String()
		}

		d.awsSyncResults[fetcher.DiscoveryConfigName()] = append(d.awsSyncResults[fetcher.DiscoveryConfigName()], fetcherResult)
	}
}

func (d *awsSyncStatus) discoveryConfigs() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ret := make([]string, 0, len(d.awsSyncResults))
	for k := range d.awsSyncResults {
		ret = append(ret, k)
	}
	return ret
}

func (d *awsSyncStatus) iterationStarted(fetchers []aws_sync.AWSSync, lastUpdate time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.awsSyncResults = make(map[string][]awsSyncResult)
	for _, fetcher := range fetchers {
		// Only update the status for fetchers that are from the discovery config.
		if !fetcher.IsFromDiscoveryConfig() {
			continue
		}

		fetcherResult := awsSyncResult{
			state:        discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_SYNCING.String(),
			lastSyncTime: lastUpdate,
		}

		d.awsSyncResults[fetcher.DiscoveryConfigName()] = append(d.awsSyncResults[fetcher.DiscoveryConfigName()], fetcherResult)
	}
}

func (d *awsSyncStatus) mergeIntoGlobalStatus(discoveryConfigName string, existingStatus discoveryconfig.Status) discoveryconfig.Status {
	d.mu.RLock()
	defer d.mu.RUnlock()

	awsStatusFetchers, found := d.awsSyncResults[discoveryConfigName]
	if !found {
		return existingStatus
	}

	var statusErrorMessages []string
	if existingStatus.ErrorMessage != nil {
		statusErrorMessages = append(statusErrorMessages, *existingStatus.ErrorMessage)
	}
	for _, fetcher := range awsStatusFetchers {
		existingStatus.DiscoveredResources = existingStatus.DiscoveredResources + fetcher.discoveredResources

		// Each DiscoveryConfigStatus has a global State and Error Message, but those are produced per Fetcher.
		// We choose to keep the most informative states by favoring error states/messages.
		if fetcher.errorMessage != nil {
			statusErrorMessages = append(statusErrorMessages, *fetcher.errorMessage)
		}

		if existingStatus.State != discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_ERROR.String() {
			existingStatus.State = fetcher.state
		}

		// Keep the earliest sync time.
		if existingStatus.LastSyncTime.After(fetcher.lastSyncTime) {
			existingStatus.LastSyncTime = fetcher.lastSyncTime
		}
	}

	if len(statusErrorMessages) > 0 {
		newErrorMessage := strings.Join(statusErrorMessages, "\n")
		existingStatus.ErrorMessage = &newErrorMessage
	}

	return existingStatus
}

func newAWSResourceStatusCollector(resourceType string) awsResourcesStatus {
	return awsResourcesStatus{
		resourceType: resourceType,
	}
}

// awsResourcesStatus contains all the status for AWS Matchers grouped by DiscoveryConfig for a specific matcher type.
type awsResourcesStatus struct {
	mu sync.RWMutex
	// awsResourcesResults maps the DiscoveryConfig name and integration to a summary of discovered/enrolled resources.
	awsResourcesResults map[awsResourceGroup]awsResourceGroupResult
	resourceType        string
}

// awsResourceGroup is the key for the summary
type awsResourceGroup struct {
	discoveryConfigName string
	integration         string
}

func awsResourceGroupFromLabels(labels map[string]string) awsResourceGroup {
	return awsResourceGroup{
		discoveryConfigName: labels[types.TeleportInternalDiscoveryConfigName],
		integration:         labels[types.TeleportInternalDiscoveryIntegrationName],
	}
}

// awsResourceGroupResult stores the result of the aws_sync Matchers for a given DiscoveryConfig.
type awsResourceGroupResult struct {
	found    int
	enrolled int
	failed   int
}

func (d *awsResourcesStatus) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.awsResourcesResults = make(map[awsResourceGroup]awsResourceGroupResult)
}

func (ars *awsResourcesStatus) mergeIntoGlobalStatus(discoveryConfigName string, existingStatus discoveryconfig.Status) discoveryconfig.Status {
	ars.mu.RLock()
	defer ars.mu.RUnlock()

	for group, groupResult := range ars.awsResourcesResults {
		if group.discoveryConfigName != discoveryConfigName {
			continue
		}

		// Update global discovered resources count.
		existingStatus.DiscoveredResources = existingStatus.DiscoveredResources + uint64(groupResult.found)

		// Update counters specific to AWS resources discovered.
		existingIntegrationResources, ok := existingStatus.IntegrationDiscoveredResources[group.integration]
		if !ok {
			existingIntegrationResources = &discoveryconfigv1.IntegrationDiscoveredSummary{}
		}

		resourcesSummary := &discoveryconfigv1.ResourcesDiscoveredSummary{
			Found:    uint64(groupResult.found),
			Enrolled: uint64(groupResult.enrolled),
			Failed:   uint64(groupResult.failed),
		}

		switch ars.resourceType {
		case types.AWSMatcherEC2:
			existingIntegrationResources.AwsEc2 = resourcesSummary
		case types.AWSMatcherRDS:
			existingIntegrationResources.AwsRds = resourcesSummary
		case types.AWSMatcherEKS:
			existingIntegrationResources.AwsEks = resourcesSummary
		}
		existingStatus.IntegrationDiscoveredResources[group.integration] = existingIntegrationResources
	}

	return existingStatus
}

func (ars *awsResourcesStatus) incrementFailed(g awsResourceGroup, count int) {
	ars.mu.Lock()
	defer ars.mu.Unlock()
	if ars.awsResourcesResults == nil {
		ars.awsResourcesResults = make(map[awsResourceGroup]awsResourceGroupResult)
	}
	groupStats := ars.awsResourcesResults[g]
	groupStats.failed = groupStats.failed + count
	ars.awsResourcesResults[g] = groupStats
}

func (ars *awsResourcesStatus) incrementFound(g awsResourceGroup, count int) {
	ars.mu.Lock()
	defer ars.mu.Unlock()
	if ars.awsResourcesResults == nil {
		ars.awsResourcesResults = make(map[awsResourceGroup]awsResourceGroupResult)
	}
	groupStats := ars.awsResourcesResults[g]
	groupStats.found = groupStats.found + count
	ars.awsResourcesResults[g] = groupStats
}

func (ars *awsResourcesStatus) incrementEnrolled(g awsResourceGroup, count int) {
	ars.mu.Lock()
	defer ars.mu.Unlock()
	if ars.awsResourcesResults == nil {
		ars.awsResourcesResults = make(map[awsResourceGroup]awsResourceGroupResult)
	}
	groupStats := ars.awsResourcesResults[g]
	groupStats.enrolled = groupStats.enrolled + count
	ars.awsResourcesResults[g] = groupStats
}

// ReportEC2SSMInstallationResult is called when discovery gets the result of running the installation script in a EC2 instance.
// It will emit an audit event with the result and update the DiscoveryConfig status
func (s *Server) ReportEC2SSMInstallationResult(ctx context.Context, result *server.SSMInstallationResult) error {
	if err := s.Emitter.EmitAuditEvent(ctx, result.SSMRunEvent); err != nil {
		return trace.Wrap(err)
	}

	// Only failed runs are counted.
	// Successful ones only mean that the teleport was installed in the target host.
	// If they succeed in joining the cluster, during the next iteration, they will be countd as "enrolled"
	if result.SSMRunEvent.Metadata.Code == libevents.SSMRunSuccessCode {
		return nil
	}

	s.awsEC2ResourcesStatus.incrementFailed(awsResourceGroup{
		discoveryConfigName: result.DiscoveryConfigName,
		integration:         result.IntegrationName,
	}, 1)

	s.updateDiscoveryConfigStatus(result.DiscoveryConfigName)

	s.awsEC2Tasks.addFailedEnrollment(
		awsEC2TaskKey{
			integration:     result.IntegrationName,
			issueType:       result.IssueType,
			accountID:       result.SSMRunEvent.AccountID,
			region:          result.SSMRunEvent.Region,
			ssmDocument:     result.SSMDocumentName,
			installerScript: result.InstallerScript,
		},
		&usertasksv1.DiscoverEC2Instance{
			InvocationUrl:   result.SSMRunEvent.InvocationURL,
			DiscoveryConfig: result.DiscoveryConfigName,
			DiscoveryGroup:  s.DiscoveryGroup,
			SyncTime:        timestamppb.New(result.SSMRunEvent.Time),
			InstanceId:      result.SSMRunEvent.InstanceID,
			Name:            result.InstanceName,
		},
	)

	return nil
}

// awsEC2Tasks contains the Discover EC2 User Tasks that must be reported to the user.
type awsEC2Tasks struct {
	mu sync.RWMutex
	// instancesIssues maps the Discover EC2 User Task grouping parts to a set of instances metadata.
	instancesIssues map[awsEC2TaskKey]*usertasksv1.DiscoverEC2
	// issuesSyncQueue is used to register which groups were changed in memory but were not yet sent to the cluster.
	// When upserting User Tasks, if the group is not in issuesSyncQueue,
	// then the cluster already has the latest version of this particular group.
	issuesSyncQueue map[awsEC2TaskKey]struct{}
}

// awsEC2TaskKey identifies a UserTask group.
type awsEC2TaskKey struct {
	integration     string
	issueType       string
	accountID       string
	region          string
	ssmDocument     string
	installerScript string
}

// reset clears out any in memory issues that were recorded.
// This is used when starting a new Auto Discover EC2 watcher iteration.
func (d *awsEC2Tasks) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.instancesIssues = make(map[awsEC2TaskKey]*usertasksv1.DiscoverEC2)
	d.issuesSyncQueue = make(map[awsEC2TaskKey]struct{})
}

// addFailedEnrollment adds an enrollment failure of a given instance.
func (d *awsEC2Tasks) addFailedEnrollment(g awsEC2TaskKey, instance *usertasksv1.DiscoverEC2Instance) {
	// Only failures associated with an Integration are reported.
	// There's no major blocking for showing non-integration User Tasks, but this keeps scope smaller.
	if g.integration == "" {
		return
	}
	if g.issueType == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.instancesIssues == nil {
		d.instancesIssues = make(map[awsEC2TaskKey]*usertasksv1.DiscoverEC2)
	}
	if _, ok := d.instancesIssues[g]; !ok {
		d.instancesIssues[g] = &usertasksv1.DiscoverEC2{
			Instances:       make(map[string]*usertasksv1.DiscoverEC2Instance),
			AccountId:       g.accountID,
			Region:          g.region,
			SsmDocument:     g.ssmDocument,
			InstallerScript: g.installerScript,
		}
	}
	d.instancesIssues[g].Instances[instance.InstanceId] = instance

	if d.issuesSyncQueue == nil {
		d.issuesSyncQueue = make(map[awsEC2TaskKey]struct{})
	}
	d.issuesSyncQueue[g] = struct{}{}
}

// awsEKSTasks contains the Discover EKS User Tasks that must be reported to the user.
type awsEKSTasks struct {
	mu sync.RWMutex
	// clusterIssues maps the EKS Task Key to a set of clusters.
	// Each Task Key represents a single User Task that is going to be created for a set of EKS Clusters that suffer from the same issue.
	clusterIssues map[awsEKSTaskKey]*usertasksv1.DiscoverEKS
	// issuesSyncQueue is used to register which groups were changed in memory but were not yet sent to the cluster.
	// When upserting User Tasks, if the group is not in issuesSyncQueue,
	// then the cluster already has the latest version of this particular group.
	issuesSyncQueue map[awsEKSTaskKey]struct{}
}

// awsEKSTaskKey identifies a UserTask group.
type awsEKSTaskKey struct {
	integration     string
	issueType       string
	accountID       string
	region          string
	appAutoDiscover bool
}

// reset clears out any in memory issues that were recorded.
// This is used when starting a new Auto Discover EKS watcher iteration.
func (d *awsEKSTasks) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.clusterIssues = make(map[awsEKSTaskKey]*usertasksv1.DiscoverEKS)
	d.issuesSyncQueue = make(map[awsEKSTaskKey]struct{})
}

// addFailedEnrollment adds an enrollment failure of a given cluster.
func (d *awsEKSTasks) addFailedEnrollment(g awsEKSTaskKey, cluster *usertasksv1.DiscoverEKSCluster) {
	// Only failures associated with an Integration are reported.
	// There's no major blocking for showing non-integration User Tasks, but this keeps scope smaller.
	if g.integration == "" {
		return
	}

	if g.issueType == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.clusterIssues == nil {
		d.clusterIssues = make(map[awsEKSTaskKey]*usertasksv1.DiscoverEKS)
	}
	if _, ok := d.clusterIssues[g]; !ok {
		d.clusterIssues[g] = &usertasksv1.DiscoverEKS{
			Clusters:        make(map[string]*usertasksv1.DiscoverEKSCluster),
			AccountId:       g.accountID,
			Region:          g.region,
			AppAutoDiscover: g.appAutoDiscover,
		}
	}
	d.clusterIssues[g].Clusters[cluster.Name] = cluster

	if d.issuesSyncQueue == nil {
		d.issuesSyncQueue = make(map[awsEKSTaskKey]struct{})
	}
	d.issuesSyncQueue[g] = struct{}{}
}

func (s *Server) acquireSemaphore(kind, semaphoreName string) (releaseFn func(), stopCtx context.Context, err error) {
	semaphoreExpiration := 5 * time.Second

	// AcquireSemaphoreLock will retry until the semaphore is acquired.
	// This prevents multiple discovery services to write AWS resources in parallel.
	// lease must be released to cleanup the resource in auth server.
	lease, err := services.AcquireSemaphoreLockWithRetry(
		s.ctx,
		services.SemaphoreLockConfigWithRetry{
			SemaphoreLockConfig: services.SemaphoreLockConfig{
				Service: s.AccessPoint,
				Params: types.AcquireSemaphoreRequest{
					SemaphoreKind: kind,
					SemaphoreName: semaphoreName,
					MaxLeases:     1,
					Holder:        s.Config.ServerID,
				},
				Expiry: semaphoreExpiration,
				Clock:  s.clock,
			},
			Retry: retryutils.LinearConfig{
				Clock:  s.clock,
				First:  time.Second,
				Step:   semaphoreExpiration / 2,
				Max:    semaphoreExpiration,
				Jitter: retryutils.DefaultJitter,
			},
		},
	)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	// Once the lease parent context is canceled, the lease will be released.
	ctxWithLease, cancel := context.WithCancel(lease)

	releaseFn = func() {
		cancel()
		lease.Stop()
		if err := lease.Wait(); err != nil {
			s.Log.WarnContext(s.ctx, "Error cleaning up semaphore", "semaphore_kind", kind, "semaphore", semaphoreName, "error", err)
		}
	}

	return releaseFn, ctxWithLease, nil
}

// acquireSemaphoreForIntegration tries to acquire a semaphore lock for the integration.
// This allows the process to do two things:
// - merge the current UserTask with the one stored in the backend, so that no task items are lost
// - ensure a single Notification (pending-user-task-integration) is created
// The former could be achieved using the UserTask name as lock identifier.
// However, for the latter, we would need a lock for the Integration.
// Instead of having two locks, locking by the Integration allows us to safely edit both resources.
//
// Note: UserTask name is a deterministic value, based on multiple fields, including the integration.
// Note: UpsertUserTask triggers the creation of a new Notification.
func (s *Server) acquireSemaphoreForIntegration(integration string) (releaseFn func(), ctx context.Context, err error) {
	return s.acquireSemaphore(types.KindIntegration, integration)
}

// mergeUpsertDiscoverEC2Task takes the current DiscoverEC2 User Task issues stored in memory and
// merges them against the ones that exist in the cluster.
//
// All of this flow is protected by a lock to ensure there's no race between this and other DiscoveryServices.
func (s *Server) mergeUpsertDiscoverEC2Task(taskGroup awsEC2TaskKey, failedInstances *usertasksv1.DiscoverEC2) error {
	if len(failedInstances.Instances) == 0 {
		return nil
	}

	userTaskName := usertasks.TaskNameForDiscoverEC2(usertasks.TaskNameForDiscoverEC2Parts{
		Integration:     taskGroup.integration,
		IssueType:       taskGroup.issueType,
		AccountID:       taskGroup.accountID,
		Region:          taskGroup.region,
		SSMDocument:     taskGroup.ssmDocument,
		InstallerScript: taskGroup.installerScript,
	})

	releaseFn, ctxWithLease, err := s.acquireSemaphoreForIntegration(taskGroup.integration)
	if err != nil {
		return trace.Wrap(err)
	}
	defer releaseFn()

	// Fetch the current task because it might have instances discovered by another group of DiscoveryServices.
	currentUserTask, err := s.AccessPoint.GetUserTask(ctxWithLease, userTaskName)
	switch {
	case trace.IsNotFound(err):
	case err != nil:
		return trace.Wrap(err)
	default:
		failedInstances = s.discoverEC2UserTaskAddExistingInstances(currentUserTask, failedInstances)
	}

	// If the DiscoveryService is stopped, or the issue does not happen again
	// the task is removed to prevent users from working on issues that are no longer happening.
	taskExpiration := s.clock.Now().Add(2 * s.PollInterval)

	task, err := usertasks.NewDiscoverEC2UserTask(
		&usertasksv1.UserTaskSpec{
			Integration: taskGroup.integration,
			TaskType:    usertasks.TaskTypeDiscoverEC2,
			IssueType:   taskGroup.issueType,
			State:       usertasks.TaskStateOpen,
			DiscoverEc2: failedInstances,
		},
		usertasks.WithExpiration(taskExpiration),
	)
	if err != nil {
		return trace.Wrap(err)
	}

	if _, err := s.AccessPoint.UpsertUserTask(ctxWithLease, task); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// discoverEC2UserTaskAddExistingInstances takes the UserTask stored in the cluster and merges it into the existing map of failed instances.
func (s *Server) discoverEC2UserTaskAddExistingInstances(currentUserTask *usertasksv1.UserTask, failedInstances *usertasksv1.DiscoverEC2) *usertasksv1.DiscoverEC2 {
	for existingInstanceID, existingInstance := range currentUserTask.Spec.DiscoverEc2.Instances {
		// Each DiscoveryService works on all the DiscoveryConfigs assigned to a given DiscoveryGroup.
		// So, it's safe to say that current DiscoveryService has the last state for a given DiscoveryGroup.
		// If other instances exist for this DiscoveryGroup, they can be discarded because, as said before, the current DiscoveryService has the last state for a given DiscoveryGroup.
		if existingInstance.DiscoveryGroup == s.DiscoveryGroup {
			continue
		}

		// For existing instances whose sync time is too far in the past, just drop them.
		// This ensures that if an instance is removed from AWS, it will eventually disappear from the User Tasks' instance list.
		// It might also be the case that the DiscoveryConfig was changed and the instance is no longer matched (because of labels/regions or other matchers).
		instanceIssueExpiration := s.clock.Now().Add(-2 * s.PollInterval)
		if existingInstance.SyncTime.AsTime().Before(instanceIssueExpiration) {
			continue
		}

		// Merge existing cluster state into in-memory object.
		failedInstances.Instances[existingInstanceID] = existingInstance
	}
	return failedInstances
}

func (s *Server) upsertTasksForAWSEC2FailedEnrollments() {
	s.awsEC2Tasks.mu.Lock()
	defer s.awsEC2Tasks.mu.Unlock()
	for g := range s.awsEC2Tasks.issuesSyncQueue {
		if err := s.mergeUpsertDiscoverEC2Task(g, s.awsEC2Tasks.instancesIssues[g]); err != nil {
			s.Log.WarnContext(s.ctx, "Failed to create discover ec2 user task",
				"integration", g.integration,
				"issue_type", g.issueType,
				"aws_account_id", g.accountID,
				"aws_region", g.region,
				"error", err,
			)
			continue
		}

		delete(s.awsEC2Tasks.issuesSyncQueue, g)
	}
}

func (s *Server) upsertTasksForAWSEKSFailedEnrollments() {
	s.awsEKSTasks.mu.Lock()
	defer s.awsEKSTasks.mu.Unlock()
	for g := range s.awsEKSTasks.issuesSyncQueue {
		if err := s.mergeUpsertDiscoverEKSTask(g, s.awsEKSTasks.clusterIssues[g]); err != nil {
			s.Log.WarnContext(s.ctx, "Failed to create discover eks user task",
				"integration", g.integration,
				"issue_type", g.issueType,
				"aws_account_id", g.accountID,
				"aws_region", g.region,
				"error", err,
			)
			continue
		}

		delete(s.awsEKSTasks.issuesSyncQueue, g)
	}
}

// mergeUpsertDiscoverEKSTask takes the current DiscoverEKS User Task issues stored in memory and
// merges them against the ones that exist in the cluster.
//
// All of this flow is protected by a lock to ensure there's no race between this and other DiscoveryServices.
func (s *Server) mergeUpsertDiscoverEKSTask(taskGroup awsEKSTaskKey, failedClusters *usertasksv1.DiscoverEKS) error {
	if len(failedClusters.Clusters) == 0 {
		return nil
	}

	userTaskName := usertasks.TaskNameForDiscoverEKS(usertasks.TaskNameForDiscoverEKSParts{
		Integration:     taskGroup.integration,
		IssueType:       taskGroup.issueType,
		AccountID:       taskGroup.accountID,
		Region:          taskGroup.region,
		AppAutoDiscover: taskGroup.appAutoDiscover,
	})

	releaseFn, ctxWithLease, err := s.acquireSemaphoreForIntegration(taskGroup.integration)
	if err != nil {
		return trace.Wrap(err)
	}
	defer releaseFn()

	// Fetch the current task because it might have instances discovered by another group of DiscoveryServices.
	currentUserTask, err := s.AccessPoint.GetUserTask(ctxWithLease, userTaskName)
	switch {
	case trace.IsNotFound(err):
	case err != nil:
		return trace.Wrap(err)
	default:
		failedClusters = s.discoverEKSUserTaskAddExistingClusters(currentUserTask, failedClusters)
	}

	// If the DiscoveryService is stopped, or the issue does not happen again
	// the task is removed to prevent users from working on issues that are no longer happening.
	taskExpiration := s.clock.Now().Add(2 * s.PollInterval)

	task, err := usertasks.NewDiscoverEKSUserTask(
		&usertasksv1.UserTaskSpec{
			Integration: taskGroup.integration,
			TaskType:    usertasks.TaskTypeDiscoverEKS,
			IssueType:   taskGroup.issueType,
			State:       usertasks.TaskStateOpen,
			DiscoverEks: failedClusters,
		},
		usertasks.WithExpiration(taskExpiration),
	)
	if err != nil {
		return trace.Wrap(err)
	}

	if _, err := s.AccessPoint.UpsertUserTask(ctxWithLease, task); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// discoverEKSUserTaskAddExistingClusters takes the UserTask stored in the cluster and merges it into the existing map of failed clusters.
func (s *Server) discoverEKSUserTaskAddExistingClusters(currentUserTask *usertasksv1.UserTask, failedClusters *usertasksv1.DiscoverEKS) *usertasksv1.DiscoverEKS {
	for existingClusterName, existingCluster := range currentUserTask.Spec.DiscoverEks.Clusters {
		// Each DiscoveryService works on all the DiscoveryConfigs assigned to a given DiscoveryGroup.
		// So, it's safe to say that current DiscoveryService has the last state for a given DiscoveryGroup.
		// If other clusters exist for this DiscoveryGroup, they can be discarded because, as said before, the current DiscoveryService has the last state for a given DiscoveryGroup.
		if existingCluster.DiscoveryGroup == s.DiscoveryGroup {
			continue
		}

		// For existing clusters whose sync time is too far in the past, just drop them.
		// This ensures that if a cluster is removed from AWS, it will eventually disappear from the User Tasks' cluster list.
		// It might also be the case that the DiscoveryConfig was changed and the cluster is no longer matched (because of labels/regions or other matchers).
		clusterIssueExpiration := s.clock.Now().Add(-2 * s.PollInterval)
		if existingCluster.SyncTime.AsTime().Before(clusterIssueExpiration) {
			continue
		}

		// Merge existing cluster state into in-memory object.
		failedClusters.Clusters[existingClusterName] = existingCluster
	}
	return failedClusters
}
