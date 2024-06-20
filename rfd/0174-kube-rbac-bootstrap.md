---
authors: Anton Miniailo (anton@goteleport.com)
state: draft
---

# RFD 174 - Kubernetes RBAC Bootstrap

## Required Approvers

- Engineering: `@rosstimothy` && (`@tigrato` || `@hugoShaka`)
- Product: `@klizhentas` || `@xinding33`

## What

Improve RBAC setup capabilities for Kubernetes and make it easier to use with Teleport by exposing
the default Kubernetes user-facing roles and adding the ability to define RBAC setup to be
automatically provisioned to Kubernetes clusters.

## Why

Currently, users have to rely on third-party tools or manual actions
when making sure their Kubernetes clusters have the correct roles/role bindings and that those are in sync with the RBAC setup defined in Teleport.
The changes we propose will make it easier for clients to start using Teleport for accessing Kubernetes clusters.

## Scope

This RFD is focused only on Kubernetes resources related to RBAC functionality, other types of resources are out of scope,
though they might be added in the future.

## Details

### Exposing the default Kubernetes user facing cluster roles (cluster-admin, view, edit)

Kubernetes clusters have default user-facing cluster roles: cluster-admin, view, edit. By default they are not usable, because
they are not exposed through role bindings to any subjects (the cluster-admin role has internal Kubernetes bindings). 
Currently, we only expose the cluster-admin role on GKE
installations, since system:masters group is not available for impersonation there. We will expand on this and when
discovering a cluster/installing kube-agent/creating a service account, we will
create cluster role bindings for those roles, accordingly linking them to the groups "default-cluster-admin", "default-view" and
"default-edit". It will give users an opportunity to always have standard set of Kubernetes permissions which they can use together
with Teleport's fine-grained RBAC definitions for Kubernetes. This will make enrolling and starting using Kubernetes clusters
into Teleport a much simpler process, since user will be able to setup RBAC completely in Teleport if they want. For example,
role giving read-only access to staging namespace pods might look like this:

```yaml
kind: role
metadata:
  name: staging-kube-access
version: v7
spec:
  allow:
    kubernetes_labels:
      'region': '*'
      'platform': 'aws'
    kubernetes_resources:
      - kind: pod
        namespace: "staging"
        name: "*"
    kubernetes_groups:
    - default-view
    kubernetes_users:
    - developer
  deny: {}
```

Users will not need to create a separate role binding in Kubernetes for it to work - once the cluster is enrolled in Teleport, the default-view is already there.
We will add an option to the teleport-kube-agent chart and to our
kubeconfig generation script to not create those cluster role bindings, but it will be enabled by default. 

### Automatically provisioning RBAC resources to Kubernetes clusters.

We will add a new type of resources, called "KubeProvision", where user will be able to specify Kubernetes RBAC resources they want to
be provisioned onto their Kubernetes clusters.
clusters. A single Teleport resource of that type can define multiple Kubernetes RBAC resources. There's a limit on size of a resource Teleport
can save on the backend, therefore, if some users would have unusually large amount of Kubernetes RBAC resources they want to provision, they would
need to split it into two KubeProvision resources.

```protobuf
import "teleport/header/v1/metadata.proto";

// KubeProvision represents a Kubernetes resources that can be provisioned on the Kubernetes clusters.
// This includes roles/role bindings and cluster roles/cluster role bindings.
// For rationale behind this type, see the RFD 174.
message KubeProvision {
  // The kind of resource represented.
  string kind = 1;
  // Not populated for this resource type.
  string sub_kind = 2;
  // The version of the resource being represented.
  string version = 3;
  // Common metadata that all resources share.
  teleport.header.v1.Metadata metadata = 4;
  // The specific properties of kube provision.
  KubeProvisionSpec spec = 5;
}

// KubeProvisionSpec is the spec for the kube provision message.
message KubeProvisionSpec {
  // resources_data is base64 encoded YAML definitions of the Kubernetes resources.
  string resources_data = 3;
}
```

Every five minutes we will run a reconciliation loop that will compare the current state on Kubernetes clusters under
Teleport management with the desired state and update the cluster's RBAC if there's a difference.

Teleport will mark RBAC resources under its control with the "app.kubernetes.io/managed-by: Teleport" label. That way we will
separate resources managed by Teleport and those managed by the user manually.

Resource labels will be taken into account when doing the reconciliation - users will be able to match different
Kubernetes clusters for different KubeProvision resources. If a KubeProvision resource doesn't have any labels defined it
will not match any clusters, effectively being disabled.

In order to be able to reconcile the state, Teleport will need to perform CRUD operations on Kubernetes RBAC resources.
When performing CRUD operations, Teleport will impersonate the "default-cluster-admin" group, that was described in the previous
section. This means that only newly enrolled
Kubernetes clusters, or cluster where the user performed a manual upgrade of permissions will be in scope of provisioning the resources,
since otherwise the "default-cluster-admin" role won't be available.

## Security

The introduction of this functionality does not directly impact the security of Teleport
itself, however it introduces a new vector of attack for a malicious actor.
Teleport user with sufficient permissions to create/edit KubeProvision resources
will be able to amend RBAC setup on all Kubernetes clusters enrolled in Teleport.
We will emphasize in the user documentation the need to be vigilant when giving out
the necessary permissions.

Even though we will always run the reconciliation loop, by default it will be a no-op, since three will
be no resources to provision, so users need to explicitly create KubeProvision resources to start actively using this new feature.
We also will explicitly require labels to be present for the resource to be provisioned to the Kubernetes cluster, making it 
more difficult to accidentally misuse the feature.

## Alternative

Alternatively, we could take a bit of a different approach regarding permissions and default roles exposure.
We could directly add permissions required to perform CRUD operations on Kubernetes RBAC resources to 
Teleport kube agent/service account credentials on enrollment. We would also ship Teleport with a default KubeProvision 
resource that defines role binding for the default user facing roles for edit and view. This default resource will not have any
labels defined, so it would not be provisioned anywhere by default. If users wanted to enable the exposure of default view/edit roles,
they would need to set labels on that resource. They can then use these roles with the fine-grained RBAC definitions for Kubernetes
in Teleport roles. This is a more conservative scenario that will require more explicit decision-making from the user. 
To expose the default Kubernetes user-facing roles, users would need to add labels to the default resource we provide,
and KubeProvisioning will only be active for clusters where Teleport has the required permissions added to its credentials.

## Future work

KubeProvision capabilities might be expanded to include any type of resource in the future, effectively acting something like a 
Terraform for Kubernetes, but defined completely in Teleport. We should gather feedback after releasing initial KubeProvision
feature to understand if there's demand for such extension of capabilities.

## Audit

No changes to the audit events will be required.

## Test plan

We will use integration tests to verify the reconciliation functionality.