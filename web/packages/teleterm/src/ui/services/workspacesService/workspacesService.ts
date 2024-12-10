/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

import { z } from 'zod';
import { arrayObjectIsEqual } from 'shared/utils/highbar';

import {
  DefaultTab,
  LabelsViewMode,
  UnifiedResourcePreferences,
  ViewMode,
  AvailableResourceMode,
} from 'gen-proto-ts/teleport/userpreferences/v1/unified_resource_preferences_pb';

import { ModalsService } from 'teleterm/ui/services/modals';
import { ClustersService } from 'teleterm/ui/services/clusters';
import {
  StatePersistenceService,
  WorkspacesPersistedState,
} from 'teleterm/ui/services/statePersistence';
import { ImmutableStore } from 'teleterm/ui/services/immutableStore';
import { NotificationsService } from 'teleterm/ui/services/notifications';
import {
  ClusterOrResourceUri,
  ClusterUri,
  DocumentUri,
  RootClusterUri,
  routing,
} from 'teleterm/ui/uri';

import {
  identitySelector,
  useStoreSelector,
} from 'teleterm/ui/hooks/useStoreSelector';
import Logger from 'teleterm/logger';

import {
  AccessRequestsService,
  getEmptyPendingAccessRequest,
  PendingAccessRequest,
} from './accessRequestsService';

import {
  Document,
  DocumentsService,
  getDefaultDocumentClusterQueryParams,
  DocumentCluster,
  DocumentGateway,
  DocumentTshKube,
  DocumentTshNode,
  createClusterDocument,
} from './documentsService';

export interface WorkspacesState {
  rootClusterUri?: RootClusterUri;
  workspaces: Record<RootClusterUri, Workspace>;
  /**
   * isInitialized signifies whether WorkspacesState has finished state restoration during the start
   * of the app. It is useful in places that want to wait for the state to be restored before
   * proceeding.
   *
   * This field is not persisted to disk.
   */
  isInitialized: boolean;
}

export interface Workspace {
  localClusterUri: ClusterUri;
  documents: Document[];
  location: DocumentUri;
  accessRequests: {
    isBarCollapsed: boolean;
    pending: PendingAccessRequest;
  };
  connectMyComputer?: {
    autoStart: boolean;
  };
  //TODO(gzdunek): Make this property required.
  // This requires updating many of tests
  // where we construct the workspace manually.
  unifiedResourcePreferences?: UnifiedResourcePreferences;
  documentsRestoredOrDiscarded?: boolean;
}

export class WorkspacesService extends ImmutableStore<WorkspacesState> {
  private documentsServicesCache = new Map<RootClusterUri, DocumentsService>();
  private accessRequestsServicesCache = new Map<
    RootClusterUri,
    AccessRequestsService
  >();
  state: WorkspacesState = {
    rootClusterUri: undefined,
    workspaces: {},
    isInitialized: false,
  };
  private restoredState?: WorkspacesPersistedState;

  constructor(
    private modalsService: ModalsService,
    private clustersService: ClustersService,
    private notificationsService: NotificationsService,
    private statePersistenceService: StatePersistenceService
  ) {
    super();
  }

  getActiveWorkspace() {
    return this.state.workspaces[this.state.rootClusterUri];
  }

  getRootClusterUri() {
    return this.state.rootClusterUri;
  }

  getWorkspaces() {
    return this.state.workspaces;
  }

  getWorkspace(clusterUri: RootClusterUri) {
    return this.state.workspaces[clusterUri];
  }

  getActiveWorkspaceDocumentService() {
    if (!this.state.rootClusterUri) {
      return;
    }
    return this.getWorkspaceDocumentService(this.state.rootClusterUri);
  }

  getActiveWorkspaceAccessRequestsService() {
    if (!this.state.rootClusterUri) {
      return;
    }
    return this.getWorkspaceAccessRequestsService(this.state.rootClusterUri);
  }

  setWorkspaceLocalClusterUri(
    clusterUri: RootClusterUri,
    localClusterUri: ClusterUri
  ): void {
    this.setState(draftState => {
      draftState.workspaces[clusterUri].localClusterUri = localClusterUri;
    });
  }

  getWorkspaceDocumentService(
    clusterUri: RootClusterUri
  ): DocumentsService | undefined {
    if (!this.documentsServicesCache.has(clusterUri)) {
      this.documentsServicesCache.set(
        clusterUri,
        new DocumentsService(
          () => {
            return this.state.workspaces[clusterUri];
          },
          newState =>
            this.setState(draftState => {
              newState(draftState.workspaces[clusterUri]);
            })
        )
      );
    }

    return this.documentsServicesCache.get(clusterUri);
  }

  getWorkspaceAccessRequestsService(
    clusterUri: RootClusterUri
  ): AccessRequestsService | undefined {
    if (!this.accessRequestsServicesCache.has(clusterUri)) {
      this.accessRequestsServicesCache.set(
        clusterUri,
        new AccessRequestsService(
          this.modalsService,
          () => {
            return this.state.workspaces[clusterUri].accessRequests;
          },
          newState =>
            this.setState(draftState => {
              newState(draftState.workspaces[clusterUri].accessRequests);
            })
        )
      );
    }
    return this.accessRequestsServicesCache.get(clusterUri);
  }

  isDocumentActive(documentUri: string): boolean {
    const documentService = this.getActiveWorkspaceDocumentService();
    return documentService && documentService.isActive(documentUri);
  }

  doesResourceBelongToActiveWorkspace(
    resourceUri: ClusterOrResourceUri
  ): boolean {
    return (
      this.state.rootClusterUri &&
      routing.belongsToProfile(this.state.rootClusterUri, resourceUri)
    );
  }

  setState(nextState: (draftState: WorkspacesState) => WorkspacesState | void) {
    super.setState(nextState);
    this.persistState();
  }

  setConnectMyComputerAutoStart(
    rootClusterUri: RootClusterUri,
    autoStart: boolean
  ): void {
    this.setState(draftState => {
      draftState.workspaces[rootClusterUri].connectMyComputer = {
        autoStart,
      };
    });
  }

  getConnectMyComputerAutoStart(rootClusterUri: RootClusterUri): boolean {
    return this.state.workspaces[rootClusterUri].connectMyComputer?.autoStart;
  }

  removeConnectMyComputerState(rootClusterUri: RootClusterUri): void {
    this.setState(draftState => {
      delete draftState.workspaces[rootClusterUri].connectMyComputer;
    });
  }

  setUnifiedResourcePreferences(
    rootClusterUri: RootClusterUri,
    preferences: UnifiedResourcePreferences
  ): void {
    this.setState(draftState => {
      draftState.workspaces[rootClusterUri].unifiedResourcePreferences =
        preferences;
    });
  }

  getUnifiedResourcePreferences(
    rootClusterUri: RootClusterUri
  ): UnifiedResourcePreferences {
    return (
      this.state.workspaces[rootClusterUri].unifiedResourcePreferences ||
      getDefaultUnifiedResourcePreferences()
    );
  }

  /**
   * setActiveWorkspace changes the active workspace to that of the given root cluster.
   * If the root cluster doesn't have a workspace yet, setActiveWorkspace creates a default
   * workspace state for the cluster and then asks the user about restoring documents from the
   * previous session if there are any.
   *
   * setActiveWorkspace never returns a rejected promise on its own.
   */
  async setActiveWorkspace(
    clusterUri: RootClusterUri,
    /**
     * Prefill values to be used in ClusterConnectDialog if the cluster is in the state but there's
     * no valid cert. The user will be asked to log in before the workspace is set as active.
     */
    prefill?: { clusterAddress: string; username: string }
  ): Promise<{
    /**
     * Determines whether the call to setActiveWorkspace actually succeeded in switching to the
     * workspace of the given cluster.
     *
     * setActiveWorkspace never rejects on its own. However, it may fail to switch to the workspace
     * if the user closes the cluster connect dialog or if the cluster with the given clusterUri
     * wasn't found.
     *
     * Callsites which don't check this return value were most likely written before this field was
     * added. They operate with the assumption that by the time the program gets to the
     * setActiveWorkspace call, the cluster must be in the state and have a valid cert, otherwise an
     * earlier action within the callsite would have failed.
     */
    isAtDesiredWorkspace: boolean;
  }> {
    if (!clusterUri) {
      this.setState(draftState => {
        draftState.rootClusterUri = undefined;
      });
      return { isAtDesiredWorkspace: true };
    }

    let cluster = this.clustersService.findCluster(clusterUri);
    if (!cluster) {
      this.notificationsService.notifyError({
        title: 'Could not set cluster as active',
        description: `Cluster with URI ${clusterUri} does not exist`,
      });
      this.logger.warn(
        `Could not find cluster with uri ${clusterUri} when changing active cluster`
      );
      return { isAtDesiredWorkspace: false };
    }

    if (cluster.profileStatusError) {
      await this.clustersService.syncRootClustersAndCatchErrors();
      // Update the cluster.
      cluster = this.clustersService.findCluster(clusterUri);
      // If the problem persists (because, for example, the user still hasn't
      // connected the hardware key) show a notification and return early.
      if (cluster.profileStatusError) {
        const notificationId = this.notificationsService.notifyError({
          title: 'Could not set cluster as active',
          description: cluster.profileStatusError,
          action: {
            content: 'Retry',
            onClick: () => {
              this.notificationsService.removeNotification(notificationId);
              this.setActiveWorkspace(clusterUri);
            },
          },
        });
        return { isAtDesiredWorkspace: false };
      }
    }

    if (!cluster.connected) {
      const connected = await new Promise<boolean>(resolve =>
        this.modalsService.openRegularDialog({
          kind: 'cluster-connect',
          clusterUri,
          reason: undefined,
          prefill,
          onCancel: () => resolve(false),
          onSuccess: () => resolve(true),
        })
      );
      if (!connected) {
        return { isAtDesiredWorkspace: false };
      }
    }
    // If we don't have a workspace for this cluster, add it.
    this.setState(draftState => {
      if (!draftState.workspaces[clusterUri]) {
        draftState.workspaces[clusterUri] =
          getWorkspaceDefaultState(clusterUri);
      }
      draftState.rootClusterUri = clusterUri;
    });

    const documentsRestoredOrDiscarded =
      this.getWorkspace(clusterUri)?.documentsRestoredOrDiscarded;
    const restoredWorkspace = this.restoredState?.workspaces?.[clusterUri];
    const askAboutRestoringDocuments =
      !documentsRestoredOrDiscarded &&
      hasDocumentsToReopen({
        previousDocuments: restoredWorkspace?.documents,
        currentDocuments: this.state.workspaces[clusterUri].documents,
      });
    if (!askAboutRestoringDocuments) {
      return { isAtDesiredWorkspace: true };
    }

    const reopen = await new Promise<boolean>(resolve =>
      this.modalsService.openRegularDialog({
        kind: 'documents-reopen',
        rootClusterUri: clusterUri,
        numberOfDocuments: restoredWorkspace.documents.length,
        onConfirm: () => resolve(true),
        onCancel: () => resolve(false),
      })
    );
    if (reopen) {
      this.reopenPreviousDocuments(clusterUri, {
        documents: restoredWorkspace.documents,
        location: restoredWorkspace.location,
      });
    } else {
      this.discardPreviousDocuments(clusterUri);
    }

    return { isAtDesiredWorkspace: true };
  }

  removeWorkspace(clusterUri: RootClusterUri): void {
    this.setState(draftState => {
      delete draftState.workspaces[clusterUri];
    });
  }

  getConnectedWorkspacesClustersUri() {
    return (Object.keys(this.state.workspaces) as RootClusterUri[]).filter(
      clusterUri => this.clustersService.findCluster(clusterUri)?.connected
    );
  }

  /**
   * Returns the state that was restored when the app was launched.
   * This state is not processed in any way, so it may, for example,
   * contain clusters that are no longer available.
   */
  getRestoredState(): WorkspacesPersistedState | undefined {
    return this.restoredState;
  }

  /**
   * Loads the state from disk into the app.
   */
  restorePersistedState(): void {
    const restoredState = this.statePersistenceService.getWorkspacesState();
    this.restoredState = restoredState;
    const restoredWorkspaces = this.clustersService
      .getRootClusters()
      .reduce((workspaces, cluster) => {
        const restoredWorkspace = restoredState.workspaces[cluster.uri];
        workspaces[cluster.uri] = getWorkspaceDefaultState(
          cluster.uri,
          restoredWorkspace
        );
        return workspaces;
      }, {});

    this.setState(draftState => {
      draftState.workspaces = restoredWorkspaces;
      draftState.isInitialized = true;
    });
  }

  private reopenPreviousDocuments(
    rootClusterUri: RootClusterUri,
    reopen: {
      documents: Document[];
      location: DocumentUri;
    }
  ): void {
    this.setState(draftState => {
      const workspace = draftState.workspaces[rootClusterUri];
      workspace.documents = reopen.documents.map(d => {
        //TODO: create a function that will prepare a new document, it will be used in:
        // DocumentsService
        // TrackedConnectionOperationsFactory
        // here
        if (
          d.kind === 'doc.terminal_tsh_kube' ||
          d.kind === 'doc.terminal_tsh_node'
        ) {
          const documentTerminal: DocumentTshKube | DocumentTshNode = {
            ...d,
            status: 'connecting',
            origin: 'reopened_session',
          };
          return documentTerminal;
        }

        if (d.kind === 'doc.gateway') {
          const documentGateway: DocumentGateway = {
            ...d,
            origin: 'reopened_session',
          };
          return documentGateway;
        }

        if (d.kind === 'doc.cluster') {
          const defaultParams = getDefaultDocumentClusterQueryParams();
          // TODO(gzdunek): this should be parsed by a tool like zod
          const documentCluster: DocumentCluster = {
            ...d,
            queryParams: {
              ...defaultParams,
              ...d.queryParams,
              sort: {
                ...defaultParams.sort,
                ...d.queryParams?.sort,
              },
            },
          };
          return documentCluster;
        }

        return d;
      });
      workspace.location = getLocationToRestore(
        reopen.documents,
        reopen.location
      );
      workspace.documentsRestoredOrDiscarded = true;
    });
  }

  private discardPreviousDocuments(clusterUri: RootClusterUri): void {
    this.setState(draftState => {
      const workspace = draftState.workspaces[clusterUri];
      workspace.documentsRestoredOrDiscarded = true;
    });
  }

  private persistState(): void {
    const stateToSave: WorkspacesPersistedState = {
      rootClusterUri: this.state.rootClusterUri,
      workspaces: {},
    };
    for (let w in this.state.workspaces) {
      const workspace = this.state.workspaces[w];
      const documentsToPersist = getDocumentsToPersist(workspace.documents);

      stateToSave.workspaces[w] = {
        localClusterUri: workspace.localClusterUri,
        location: workspace.location,
        documents: documentsToPersist,
        connectMyComputer: workspace.connectMyComputer,
        unifiedResourcePreferences: workspace.unifiedResourcePreferences,
      };
    }
    this.statePersistenceService.saveWorkspacesState(stateToSave);
  }
}

// Best to keep in sync with lib/services/local/userpreferences.go.
export function getDefaultUnifiedResourcePreferences(): UnifiedResourcePreferences {
  return {
    defaultTab: DefaultTab.ALL,
    viewMode: ViewMode.CARD,
    labelsViewMode: LabelsViewMode.COLLAPSED,
    availableResourceMode: AvailableResourceMode.NONE,
  };
}

const unifiedResourcePreferencesSchema = z
  .object({
    defaultTab: z
      .nativeEnum(DefaultTab)
      .default(getDefaultUnifiedResourcePreferences().defaultTab),
    viewMode: z
      .nativeEnum(ViewMode)
      .default(getDefaultUnifiedResourcePreferences().viewMode),
    labelsViewMode: z
      .nativeEnum(LabelsViewMode)
      .default(getDefaultUnifiedResourcePreferences().labelsViewMode),
    availableResourceMode: z
      .nativeEnum(AvailableResourceMode)
      .default(getDefaultUnifiedResourcePreferences().availableResourceMode),
  })
  // Assign the default values if undefined is passed.
  .default({});

// Because we don't have `strictNullChecks` enabled, zod infers
// all properties as optional.
// With this helper, we can enforce the schema to contain all properties.
type UnifiedResourcePreferencesSchemaAsRequired = Required<
  z.infer<typeof unifiedResourcePreferencesSchema>
>;

/**
 * useWorkspaceServiceState is a replacement for the legacy useStore hook. Many components within
 * teleterm depend on the behavior of useStore which re-renders the component on any change within
 * the store. Most of the time, those components don't even use the state returned by useStore.
 *
 * @deprecated Prefer useStoreSelector with a selector that picks only what the callsite is going
 * to use. useWorkspaceServiceState re-renders the component on any change within any workspace.
 */
export const useWorkspaceServiceState = () => {
  return useStoreSelector('workspacesService', identitySelector);
};

function getDocumentsToPersist(documents: Document[]): Document[] {
  return (
    documents
      // We don't persist 'doc.authorize_web_session' because we don't want to store
      // a session token and id on disk.
      // Moreover, the user would not be able to authorize a session at a later time anyway.
      .filter(d => d.kind !== 'doc.authorize_web_session')
  );
}

function getLocationToRestore(
  documents: Document[],
  location: DocumentUri
): DocumentUri | undefined {
  return documents.find(d => d.uri === location) ? location : documents[0]?.uri;
}

function getWorkspaceDefaultState(
  rootClusterUri: RootClusterUri,
  restoredWorkspace?: Omit<Workspace, 'accessRequests'>
): Workspace {
  const defaultDocument = createClusterDocument({ clusterUri: rootClusterUri });
  const defaultWorkspace: Workspace = {
    accessRequests: {
      pending: getEmptyPendingAccessRequest(),
      isBarCollapsed: false,
    },
    location: defaultDocument.uri,
    documents: [defaultDocument],
    connectMyComputer: undefined,
    documentsRestoredOrDiscarded: false,
    localClusterUri: rootClusterUri,
    unifiedResourcePreferences: parseUnifiedResourcePreferences(undefined),
  };
  if (restoredWorkspace) {
    defaultWorkspace.localClusterUri = restoredWorkspace.localClusterUri;
    defaultWorkspace.unifiedResourcePreferences =
      parseUnifiedResourcePreferences(
        restoredWorkspace.unifiedResourcePreferences
      );
    defaultWorkspace.connectMyComputer = restoredWorkspace.connectMyComputer;
  }

  return defaultWorkspace;
}

// TODO(gzdunek): Parse the entire workspace state read from disk like below.
function parseUnifiedResourcePreferences(
  unifiedResourcePreferences: unknown
): UnifiedResourcePreferences | undefined {
  try {
    return unifiedResourcePreferencesSchema.parse(
      unifiedResourcePreferences
    ) as UnifiedResourcePreferencesSchemaAsRequired;
  } catch (e) {
    new Logger().error('Failed to parse unified resource preferences', e);
  }
}

function hasDocumentsToReopen({
  previousDocuments,
  currentDocuments,
}: {
  previousDocuments?: Document[];
  currentDocuments: Document[];
}): boolean {
  const omitUriAndTitle = (documents: Document[]) =>
    documents.map(d => ({ ...d, uri: undefined, title: undefined }));

  return (
    previousDocuments?.length &&
    !arrayObjectIsEqual(
      omitUriAndTitle(previousDocuments),
      omitUriAndTitle(currentDocuments)
    )
  );
}
