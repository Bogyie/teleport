// Code generated by goderive DO NOT EDIT.

package discoveryconfig

import (
	types "github.com/gravitational/teleport/api/types"
	header "github.com/gravitational/teleport/api/types/header"
	utils "github.com/gravitational/teleport/api/utils"
)

// deriveTeleportEqualDiscoveryConfig returns whether this and that are equal.
func deriveTeleportEqualDiscoveryConfig(this, that *DiscoveryConfig) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual(&this.ResourceHeader, &that.ResourceHeader) &&
			deriveTeleportEqual_(&this.Spec, &that.Spec)
}

// deriveTeleportEqual returns whether this and that are equal.
func deriveTeleportEqual(this, that *header.ResourceHeader) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Kind == that.Kind &&
			this.SubKind == that.SubKind &&
			this.Version == that.Version &&
			deriveTeleportEqual_1(&this.Metadata, &that.Metadata)
}

// deriveTeleportEqual_ returns whether this and that are equal.
func deriveTeleportEqual_(this, that *Spec) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.DiscoveryGroup == that.DiscoveryGroup &&
			deriveTeleportEqual_2(this.AWS, that.AWS) &&
			deriveTeleportEqual_3(this.Azure, that.Azure) &&
			deriveTeleportEqual_4(this.GCP, that.GCP) &&
			deriveTeleportEqual_5(this.Kube, that.Kube) &&
			deriveTeleportEqual_6(this.AccessGraph, that.AccessGraph)
}

// deriveTeleportEqual_1 returns whether this and that are equal.
func deriveTeleportEqual_1(this, that *header.Metadata) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name &&
			this.Description == that.Description &&
			deriveTeleportEqual_7(this.Labels, that.Labels) &&
			this.Expires.Equal(that.Expires)
}

// deriveTeleportEqual_2 returns whether this and that are equal.
func deriveTeleportEqual_2(this, that []types.AWSMatcher) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveTeleportEqual_8(&this[i], &that[i])) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_3 returns whether this and that are equal.
func deriveTeleportEqual_3(this, that []types.AzureMatcher) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveTeleportEqual_9(&this[i], &that[i])) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_4 returns whether this and that are equal.
func deriveTeleportEqual_4(this, that []types.GCPMatcher) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveTeleportEqual_10(&this[i], &that[i])) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_5 returns whether this and that are equal.
func deriveTeleportEqual_5(this, that []types.KubernetesMatcher) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveTeleportEqual_11(&this[i], &that[i])) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_6 returns whether this and that are equal.
func deriveTeleportEqual_6(this, that *types.AccessGraphSync) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_12(this.AWS, that.AWS) &&
			deriveTeleportEqual_13(this.Azure, that.Azure) &&
			this.PollInterval == that.PollInterval
}

// deriveTeleportEqual_7 returns whether this and that are equal.
func deriveTeleportEqual_7(this, that map[string]string) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for k, v := range this {
		thatv, ok := that[k]
		if !ok {
			return false
		}
		if !(v == thatv) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_8 returns whether this and that are equal.
func deriveTeleportEqual_8(this, that *types.AWSMatcher) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_14(this.Types, that.Types) &&
			deriveTeleportEqual_14(this.Regions, that.Regions) &&
			deriveTeleportEqual_15(this.AssumeRole, that.AssumeRole) &&
			deriveTeleportEqual_16(this.Tags, that.Tags) &&
			deriveTeleportEqual_17(this.Params, that.Params) &&
			deriveTeleportEqual_18(this.SSM, that.SSM) &&
			this.Integration == that.Integration &&
			this.KubeAppDiscovery == that.KubeAppDiscovery &&
			this.SetupAccessForARN == that.SetupAccessForARN
}

// deriveTeleportEqual_9 returns whether this and that are equal.
func deriveTeleportEqual_9(this, that *types.AzureMatcher) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_14(this.Subscriptions, that.Subscriptions) &&
			deriveTeleportEqual_14(this.ResourceGroups, that.ResourceGroups) &&
			deriveTeleportEqual_14(this.Types, that.Types) &&
			deriveTeleportEqual_14(this.Regions, that.Regions) &&
			deriveTeleportEqual_16(this.ResourceTags, that.ResourceTags) &&
			deriveTeleportEqual_17(this.Params, that.Params)
}

// deriveTeleportEqual_10 returns whether this and that are equal.
func deriveTeleportEqual_10(this, that *types.GCPMatcher) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_14(this.Types, that.Types) &&
			deriveTeleportEqual_14(this.Locations, that.Locations) &&
			deriveTeleportEqual_16(this.Tags, that.Tags) &&
			deriveTeleportEqual_14(this.ProjectIDs, that.ProjectIDs) &&
			deriveTeleportEqual_14(this.ServiceAccounts, that.ServiceAccounts) &&
			deriveTeleportEqual_17(this.Params, that.Params) &&
			deriveTeleportEqual_16(this.Labels, that.Labels)
}

// deriveTeleportEqual_11 returns whether this and that are equal.
func deriveTeleportEqual_11(this, that *types.KubernetesMatcher) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_14(this.Types, that.Types) &&
			deriveTeleportEqual_14(this.Namespaces, that.Namespaces) &&
			deriveTeleportEqual_16(this.Labels, that.Labels)
}

// deriveTeleportEqual_12 returns whether this and that are equal.
func deriveTeleportEqual_12(this, that []*types.AccessGraphAWSSync) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveTeleportEqual_19(this[i], that[i])) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_13 returns whether this and that are equal.
func deriveTeleportEqual_13(this, that []*types.AccessGraphAzureSync) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveTeleportEqual_20(this[i], that[i])) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_14 returns whether this and that are equal.
func deriveTeleportEqual_14(this, that []string) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(this[i] == that[i]) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_15 returns whether this and that are equal.
func deriveTeleportEqual_15(this, that *types.AssumeRole) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.RoleARN == that.RoleARN &&
			this.ExternalID == that.ExternalID
}

// deriveTeleportEqual_16 returns whether this and that are equal.
func deriveTeleportEqual_16(this, that map[string]utils.Strings) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for k, v := range this {
		thatv, ok := that[k]
		if !ok {
			return false
		}
		if !(deriveTeleportEqual_14(v, thatv)) {
			return false
		}
	}
	return true
}

// deriveTeleportEqual_17 returns whether this and that are equal.
func deriveTeleportEqual_17(this, that *types.InstallerParams) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.JoinMethod == that.JoinMethod &&
			this.JoinToken == that.JoinToken &&
			this.ScriptName == that.ScriptName &&
			this.InstallTeleport == that.InstallTeleport &&
			this.SSHDConfig == that.SSHDConfig &&
			this.PublicProxyAddr == that.PublicProxyAddr &&
			deriveTeleportEqual_21(this.Azure, that.Azure) &&
			this.EnrollMode == that.EnrollMode
}

// deriveTeleportEqual_18 returns whether this and that are equal.
func deriveTeleportEqual_18(this, that *types.AWSSSM) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.DocumentName == that.DocumentName
}

// deriveTeleportEqual_19 returns whether this and that are equal.
func deriveTeleportEqual_19(this, that *types.AccessGraphAWSSync) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_14(this.Regions, that.Regions) &&
			deriveTeleportEqual_15(this.AssumeRole, that.AssumeRole) &&
			this.Integration == that.Integration
}

// deriveTeleportEqual_20 returns whether this and that are equal.
func deriveTeleportEqual_20(this, that *types.AccessGraphAzureSync) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveTeleportEqual_14(this.Regions, that.Regions) &&
			this.SubscriptionID == that.SubscriptionID &&
			this.UmiClientId == that.UmiClientId &&
			this.Integration == that.Integration
}

// deriveTeleportEqual_21 returns whether this and that are equal.
func deriveTeleportEqual_21(this, that *types.AzureInstallerParams) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ClientID == that.ClientID
}
