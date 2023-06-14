// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package services

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	embeddingpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/embedding/v1"
	"github.com/gravitational/teleport/api/internalutils/stream"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/retryutils"
	"github.com/gravitational/teleport/lib/ai"
	"github.com/gravitational/teleport/lib/utils/interval"
)

// Embeddings service is responsible for storing and retrieving embeddings in
// the backend. The backend acts as an embedding cache. Embeddings can be
// re-generated by an ai.Embedder.
type Embeddings interface {
	// GetEmbedding looks up a single embedding by its name in the backend.
	GetEmbedding(ctx context.Context, kind, resourceID string) (*ai.Embedding, error)
	// GetEmbeddings returns all embeddings for a given kind.
	GetEmbeddings(ctx context.Context, kind string) stream.Stream[*ai.Embedding]
	// UpsertEmbedding creates or update a single ai.Embedding in the backend.
	UpsertEmbedding(ctx context.Context, embedding *ai.Embedding) (*ai.Embedding, error)
}

// MarshalEmbedding marshals the ai.Embedding resource to binary ProtoBuf.
func MarshalEmbedding(embedding *ai.Embedding) ([]byte, error) {
	data, err := proto.Marshal((*embeddingpb.Embedding)(embedding))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return data, nil
}

// UnmarshalEmbedding unmarshals binary ProtoBuf into an ai.Embedding resource.
func UnmarshalEmbedding(bytes []byte) (*ai.Embedding, error) {
	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing embedding data")
	}
	var embedding embeddingpb.Embedding
	err := proto.Unmarshal(bytes, &embedding)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return (*ai.Embedding)(&embedding), nil
}

// NodeEmbeddingWatcher listen for Node events and asynchronously compute
// embeddings for known nodes.
type NodeEmbeddingWatcher struct {
	*resourceWatcher
	*nodeEmbeddingCollector
}

// NewNodeEmbeddingWatcher returns a new instance of NodeEmbeddingWatcher.
func NewNodeEmbeddingWatcher(ctx context.Context, cfg NodeEmbeddingWatcherConfig) (*NodeEmbeddingWatcher, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	collector := &nodeEmbeddingCollector{
		NodeEmbeddingWatcherConfig: cfg,
		initializationC:            make(chan struct{}),
		currentNodes:               make(map[string]*embeddedNode),
	}
	// start the collector as staled.
	collector.stale.Store(true)

	watcher, err := newResourceWatcher(ctx, collector, cfg.ResourceWatcherConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &NodeEmbeddingWatcher{resourceWatcher: watcher, nodeEmbeddingCollector: collector}, nil
}

// NodeEmbeddingWatcherConfig is the configuration of the NodeEmbeddingWatcher.
// It extends the NodeWatcherConfig with a reference to the services.Embeddings.
// This way, the watcher and collector have access to the embeddings in the
// backend and can create new embeddings via the ai.Embedder.
type NodeEmbeddingWatcherConfig struct {
	NodeWatcherConfig
	Embeddings
	Embedder ai.Embedder
}

func (cfg *NodeEmbeddingWatcherConfig) CheckAndSetDefaults() error {
	if err := cfg.NodeWatcherConfig.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if cfg.Embedder == nil {
		return trace.BadParameter("embedder is not set")
	}
	return nil
}

// nodeEmbeddingCollector accompanies resourceWatcher when monitoring currentNodes.
// It keeps tracks of which node has been embedded and which node requires embedding.
// The embedding happens asynchronously as calling the openAI API by batch is
// much quicker, stable and efficient.
type nodeEmbeddingCollector struct {
	NodeEmbeddingWatcherConfig

	// initializationC is used to check whether the initial sync has completed
	// This is required for implementing the collector interface
	initializationC chan struct{}
	// once keeps track if the initialization message has already been sent
	once sync.Once

	// currentNodes holds the knwown nodes and their embedding state.
	// The map is consumed in 3 cases:
	// - during the initial or un-stale full-sync
	// - when an event comes in and changes a node's state
	// - during the embedding process
	// During the embedding process, currentNodes might be updated between the
	// read and the write operations:
	// - Additions can be ignored as they'll get picked up by the next embedding routine
	// - If an element gets deleted, the embedding routine must not add it back
	// - If an element gets updated, the timestamp will have changed and the
	//   indexation must not mark the element as embedded. It will be picked up
	//   by the next embedding routine.
	currentNodes map[string]*embeddedNode

	// mutex must be acquired before reading or writing to currentNodes
	mutex sync.Mutex
	stale atomic.Bool
}

type embeddedNode struct {
	node           types.Server
	needsEmbedding bool
	// Last update allows to avoid most race conditions
	// Before updating or deleting the node, the caller must
	// check if it has been edited in the meantime.
	lastUpdate time.Time
}

func (e *embeddedNode) gotEmbedded() {
	e.needsEmbedding = false
}

// resourceKind specifies the resource kind to watch.
func (n *nodeEmbeddingCollector) resourceKind() string {
	return types.KindNode
}

// getResourcesAndUpdateCurrent is called when the resources should be
// (re-)fetched directly.
func (n *nodeEmbeddingCollector) getResourcesAndUpdateCurrent(ctx context.Context) error {
	// We start the full sync by locking. As we are computing diff between the
	// nodes in the backend and our tracked nodes, we don't want currentNodes
	// to change until we're finish sync-ing.
	n.mutex.Lock()
	defer n.mutex.Unlock()
	timestamp := time.Now()

	allNodes, err := n.getNodes(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	toRemove := make([]string, 0)
	// If we knew a node which is not in the full node list anymore we drop
	// it from the index
	for _, knownNode := range n.currentNodes {
		if _, ok := allNodes[knownNode.node.GetName()]; !ok {
			toRemove = append(toRemove, knownNode.node.GetName())
		}
	}

	n.addNodes(allNodes, timestamp)
	n.removeNodes(toRemove, timestamp)

	n.defineCollectorAsInitialized()
	n.stale.Store(false)
	return nil
}

// addNodes takes a map of new or updated nodes, stores them and flags them for
// embedding. mutex must be acquired before calling this function. If a node's
// timestamp is newer than the provided timestamp, it will be ignored.
func (n *nodeEmbeddingCollector) addNodes(nodes map[string]types.Server, timestamp time.Time) {
	for nodeName, node := range nodes {
		// If the node is already known and has been edited in the meantime we
		// don't want to override as we don't have the latest version
		if currentNode, ok := n.currentNodes[nodeName]; ok {
			if currentNode.lastUpdate.After(timestamp) {
				continue
			}
		}
		n.currentNodes[nodeName] = &embeddedNode{
			node:           node,
			needsEmbedding: true,
			lastUpdate:     timestamp,
		}
	}
}

// removeNodes takes a list of node names, removes them from the vector index
// and from the collector tracking. mutex must be acquired before calling this
// function. If a node's timestamp is newer than the provided timestamp, it
// will be ignored.
func (n *nodeEmbeddingCollector) removeNodes(nodeNames []string, timestamp time.Time) {
	for _, nodeName := range nodeNames {
		if n.currentNodes[nodeName].lastUpdate.Before(timestamp) {
			delete(n.currentNodes, nodeName)
		}
	}
}

// RunIndexation walks through all collector-tracked nodes and runs a batch
// embedding on all nodes needing embeddings. The embeddings are then inserted
// into the vector index. This process is ran asynchronously to reduce the load
// and leverage OpenAI's batch embedding API.
func (n *nodeEmbeddingCollector) RunIndexation(ctx context.Context) error {
	n.Log.Debug("running embedding")
	// If data is stale, we attempt to refresh it, else we continue and embed
	// the stale data
	if n.stale.Load() {
		_ = n.getResourcesAndUpdateCurrent(ctx)
	}

	needsEmbedding := make(map[string][]byte)
	n.mutex.Lock()
	timestamp := time.Now()
	for nodeName, node := range n.currentNodes {
		if node.needsEmbedding {
			text, err := serializeNode(node.node)
			if err != nil {
				n.Log.Warningf("failed to serialize node %s, the node won't be embedded", node.node.GetName())
				continue
			}
			needsEmbedding[nodeName] = text
		}
	}
	n.mutex.Unlock()

	embeddings, err := n.embed(ctx, types.KindNode, needsEmbedding)
	if err != nil {
		return trace.Wrap(err)
	}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	for _, embedding := range embeddings {
		if node, ok := n.currentNodes[embedding.GetEmbeddedID()]; ok && node.lastUpdate.Before(timestamp) {
			node.gotEmbedded()
		}
	}

	n.Log.Debugf("Embedded %d nodes", len(embeddings))

	// TODO(hugoShaka): when vector index is here, delete then insert nodes in it.
	return nil
}

func (n *nodeEmbeddingCollector) getNodes(ctx context.Context) (map[string]types.Server, error) {
	nodes, err := n.NodesGetter.GetNodes(ctx, apidefaults.Namespace)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(nodes) == 0 {
		return map[string]types.Server{}, nil
	}

	current := make(map[string]types.Server, len(nodes))
	for _, node := range nodes {
		current[node.GetName()] = node
	}

	return current, nil
}

func (n *nodeEmbeddingCollector) defineCollectorAsInitialized() {
	n.once.Do(func() {
		// mark watcher as initialized.
		close(n.initializationC)
	})
}

// processEventAndUpdateCurrent is called when a watcher event is received.
func (n *nodeEmbeddingCollector) processEventAndUpdateCurrent(_ context.Context, event types.Event) {
	if event.Resource == nil || event.Resource.GetKind() != types.KindNode {
		n.Log.Warningf("Unexpected event: %v.", event)
		return
	}

	n.mutex.Lock()
	timestamp := time.Now()
	defer n.mutex.Unlock()
	switch event.Type {
	case types.OpDelete:
		n.removeNodes([]string{event.Resource.GetName()}, timestamp)
	case types.OpPut:
		server, ok := event.Resource.(types.Server)
		if !ok {
			n.Log.Warningf("Unexpected type %T.", event.Resource)
			return
		}
		n.addNodes(map[string]types.Server{server.GetName(): server}, timestamp)
	default:
		n.Log.Warningf("Skipping unsupported event type %s.", event.Type)
	}
}

func (n *nodeEmbeddingCollector) initializationChan() <-chan struct{} {
	return n.initializationC
}

func (n *nodeEmbeddingCollector) notifyStale() {
	n.stale.Store(true)
}

// NodeCount returns the number of nodes being tracked by the collector which
// have not been embedded. This function is mainly here for testing purposes.
func (n *nodeEmbeddingCollector) NodeCount(needsEmbedding bool) int {
	count := 0
	n.mutex.Lock()
	defer n.mutex.Unlock()
	for _, node := range n.currentNodes {
		if node.needsEmbedding == needsEmbedding {
			count += 1
		}
	}
	return count
}

// embed takes a resource textual representation, checks if the resource
// already has an up-to-date embedding stored in the backend, and computes
// a new embedding otherwise. The newly computed embedding is stored in
// the backend.
func (n *nodeEmbeddingCollector) embed(ctx context.Context, kind string, resources map[string][]byte) ([]*ai.Embedding, error) {

	// Lookup if there are embeddings in the backend for this node
	// and the hash matches
	embeddingsFromCache := make([]*ai.Embedding, 0)
	toEmbed := make(map[string][]byte)
	for name, data := range resources {
		existingEmbedding, err := n.GetEmbedding(ctx, kind, name)
		if err != nil && !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		if err == nil {
			if embeddingHashMatches(existingEmbedding, ai.EmbeddingHash(data)) {
				embeddingsFromCache = append(embeddingsFromCache, existingEmbedding)
				continue
			}
		}
		toEmbed[name] = data
	}

	// Convert to a list but keep track of the order so that we know which
	// input maps to which resource.
	keys := make([]string, 0, len(toEmbed))
	input := make([]string, len(toEmbed))

	for key := range toEmbed {
		keys = append(keys, key)
	}

	for i, key := range keys {
		input[i] = string(toEmbed[key])
	}

	response, err := n.Embedder.ComputeEmbeddings(ctx, input)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	newEmbeddings := make([]*ai.Embedding, 0, len(response))
	for i, vector := range response {
		newEmbeddings = append(newEmbeddings, ai.NewEmbedding(kind, keys[i], vector, ai.EmbeddingHash(resources[keys[i]])))
	}

	// Store the new embeddings into the backend
	for _, embedding := range newEmbeddings {
		_, err := n.UpsertEmbedding(ctx, embedding)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return append(embeddingsFromCache, newEmbeddings...), nil
}

func embeddingHashMatches(embedding *ai.Embedding, hash ai.Sha256Hash) bool {
	if len(embedding.EmbeddedHash) != 32 {
		return false
	}

	return *(*ai.Sha256Hash)(embedding.EmbeddedHash) == hash
}

// serializeNode converts a type.Server into text ready to be fed to an
// embedding model. The YAML serialization function was chosen over JSON and
// CSV as it provided better results.
func serializeNode(node types.Server) ([]byte, error) {
	a := struct {
		Name    string            `yaml:"name"`
		Kind    string            `yaml:"kind"`
		SubKind string            `yaml:"subkind"`
		Labels  map[string]string `yaml:"labels"`
	}{
		Name:    node.GetName(),
		Kind:    types.KindNode,
		SubKind: node.GetSubKind(),
		Labels:  node.GetAllLabels(),
	}
	text, err := yaml.Marshal(&a)
	return text, trace.Wrap(err)
}

func (n *NodeEmbeddingWatcher) RunPeriodicEmbedding(ctx context.Context, period time.Duration) {
	ticker := interval.New(interval.Config{
		Duration:      period,
		Jitter:        retryutils.NewSeventhJitter(),
		FirstDuration: time.Minute,
	})
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Next():
			err := n.RunIndexation(ctx)
			if err != nil {
				n.Log.Error(err)
			}
		}
	}

}
