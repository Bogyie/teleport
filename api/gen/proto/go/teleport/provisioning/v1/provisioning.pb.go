// Copyright 2024 Gravitational, Inc
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        (unknown)
// source: teleport/provisioning/v1/provisioning.proto

package provisioningv1

import (
	v1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// ProvisioningState indicates the current stage of the provisioning pipeline a
// resource is in.
type ProvisioningState int32

const (
	// PROVISIONING_STATE_UNSPECIFIED is the `unset` default value. This should
	// never be used in practice.
	ProvisioningState_PROVISIONING_STATE_UNSPECIFIED ProvisioningState = 0
	// PROVISIONING_STATE_STALE indicates that Teleport has detected a change in
	// the principal resource, but that has not yet been reflected in the
	// downstream system.
	ProvisioningState_PROVISIONING_STATE_STALE ProvisioningState = 1
	// PROVISIONING_STATE_PROVISIONED indicates that the principal has been synced
	// with the downstram system and no further work is necessary.
	ProvisioningState_PROVISIONING_STATE_PROVISIONED ProvisioningState = 2
	// PROVISIONING_STATE_DELETED indicates that the principal has been deleted in
	// Teleport, and must be de-provisioned in the downstream system and the
	// provisioning state record deleted.
	ProvisioningState_PROVISIONING_STATE_DELETED ProvisioningState = 3
)

// Enum value maps for ProvisioningState.
var (
	ProvisioningState_name = map[int32]string{
		0: "PROVISIONING_STATE_UNSPECIFIED",
		1: "PROVISIONING_STATE_STALE",
		2: "PROVISIONING_STATE_PROVISIONED",
		3: "PROVISIONING_STATE_DELETED",
	}
	ProvisioningState_value = map[string]int32{
		"PROVISIONING_STATE_UNSPECIFIED": 0,
		"PROVISIONING_STATE_STALE":       1,
		"PROVISIONING_STATE_PROVISIONED": 2,
		"PROVISIONING_STATE_DELETED":     3,
	}
)

func (x ProvisioningState) Enum() *ProvisioningState {
	p := new(ProvisioningState)
	*p = x
	return p
}

func (x ProvisioningState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProvisioningState) Descriptor() protoreflect.EnumDescriptor {
	return file_teleport_provisioning_v1_provisioning_proto_enumTypes[0].Descriptor()
}

func (ProvisioningState) Type() protoreflect.EnumType {
	return &file_teleport_provisioning_v1_provisioning_proto_enumTypes[0]
}

func (x ProvisioningState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ProvisioningState.Descriptor instead.
func (ProvisioningState) EnumDescriptor() ([]byte, []int) {
	return file_teleport_provisioning_v1_provisioning_proto_rawDescGZIP(), []int{0}
}

// PrincipalType indicates the type of principal represented by a PrincipalState
type PrincipalType int32

const (
	// PRINCIPAL_TYPE_UNSPECIFIED is the `unset` default value. This should
	// never be used in practice.
	PrincipalType_PRINCIPAL_TYPE_UNSPECIFIED PrincipalType = 0
	// PRINCIPAL_TYPE_USER indicates that the target principal is a Teleport user
	PrincipalType_PRINCIPAL_TYPE_USER PrincipalType = 1
	// PRINCIPAL_TYPE_USER indicates that the target principal is a Teleport
	// Access List
	PrincipalType_PRINCIPAL_TYPE_ACCESS_LIST PrincipalType = 2
)

// Enum value maps for PrincipalType.
var (
	PrincipalType_name = map[int32]string{
		0: "PRINCIPAL_TYPE_UNSPECIFIED",
		1: "PRINCIPAL_TYPE_USER",
		2: "PRINCIPAL_TYPE_ACCESS_LIST",
	}
	PrincipalType_value = map[string]int32{
		"PRINCIPAL_TYPE_UNSPECIFIED": 0,
		"PRINCIPAL_TYPE_USER":        1,
		"PRINCIPAL_TYPE_ACCESS_LIST": 2,
	}
)

func (x PrincipalType) Enum() *PrincipalType {
	p := new(PrincipalType)
	*p = x
	return p
}

func (x PrincipalType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PrincipalType) Descriptor() protoreflect.EnumDescriptor {
	return file_teleport_provisioning_v1_provisioning_proto_enumTypes[1].Descriptor()
}

func (PrincipalType) Type() protoreflect.EnumType {
	return &file_teleport_provisioning_v1_provisioning_proto_enumTypes[1]
}

func (x PrincipalType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PrincipalType.Descriptor instead.
func (PrincipalType) EnumDescriptor() ([]byte, []int) {
	return file_teleport_provisioning_v1_provisioning_proto_rawDescGZIP(), []int{1}
}

// PrincipalState describes the provisioning state of a Teleport user in a
// downstream system
type PrincipalState struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Kind     string                `protobuf:"bytes,1,opt,name=kind,proto3" json:"kind,omitempty"`
	SubKind  string                `protobuf:"bytes,2,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	Version  string                `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	Metadata *v1.Metadata          `protobuf:"bytes,4,opt,name=metadata,proto3" json:"metadata,omitempty"`
	Spec     *PrincipalStateSpec   `protobuf:"bytes,5,opt,name=spec,proto3" json:"spec,omitempty"`
	Status   *PrincipalStateStatus `protobuf:"bytes,6,opt,name=status,proto3" json:"status,omitempty"`
}

func (x *PrincipalState) Reset() {
	*x = PrincipalState{}
	mi := &file_teleport_provisioning_v1_provisioning_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PrincipalState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PrincipalState) ProtoMessage() {}

func (x *PrincipalState) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_provisioning_v1_provisioning_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PrincipalState.ProtoReflect.Descriptor instead.
func (*PrincipalState) Descriptor() ([]byte, []int) {
	return file_teleport_provisioning_v1_provisioning_proto_rawDescGZIP(), []int{0}
}

func (x *PrincipalState) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *PrincipalState) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *PrincipalState) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *PrincipalState) GetMetadata() *v1.Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *PrincipalState) GetSpec() *PrincipalStateSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

func (x *PrincipalState) GetStatus() *PrincipalStateStatus {
	if x != nil {
		return x.Status
	}
	return nil
}

// PrincipalStateSpec describes the current state of a provisioning operation. It
// serves as a Teleport-local record of the downstream state.
type PrincipalStateSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// DownstreamId identifies the downstream service that this state applies to.
	DownstreamId string `protobuf:"bytes,1,opt,name=downstream_id,json=downstreamId,proto3" json:"downstream_id,omitempty"`
	// PrincipalType identifies what kind of principal this state applies to, either
	// a User or a Group (i.e. AccessList)
	PrincipalType PrincipalType `protobuf:"varint,2,opt,name=principal_type,json=principalType,proto3,enum=teleport.provisioning.v1.PrincipalType" json:"principal_type,omitempty"`
	// PrincipalId identifies the Teleport User or Access List that this state
	// applies to
	PrincipalId string `protobuf:"bytes,3,opt,name=principal_id,json=principalId,proto3" json:"principal_id,omitempty"`
}

func (x *PrincipalStateSpec) Reset() {
	*x = PrincipalStateSpec{}
	mi := &file_teleport_provisioning_v1_provisioning_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PrincipalStateSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PrincipalStateSpec) ProtoMessage() {}

func (x *PrincipalStateSpec) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_provisioning_v1_provisioning_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PrincipalStateSpec.ProtoReflect.Descriptor instead.
func (*PrincipalStateSpec) Descriptor() ([]byte, []int) {
	return file_teleport_provisioning_v1_provisioning_proto_rawDescGZIP(), []int{1}
}

func (x *PrincipalStateSpec) GetDownstreamId() string {
	if x != nil {
		return x.DownstreamId
	}
	return ""
}

func (x *PrincipalStateSpec) GetPrincipalType() PrincipalType {
	if x != nil {
		return x.PrincipalType
	}
	return PrincipalType_PRINCIPAL_TYPE_UNSPECIFIED
}

func (x *PrincipalStateSpec) GetPrincipalId() string {
	if x != nil {
		return x.PrincipalId
	}
	return ""
}

// PrincipalStateStatus contains the runtime-writable status block for the
// PrincipalState resource
type PrincipalStateStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ProvisioningState indicates the resource's current state in the
	// provisioning process state machine.
	ProvisioningState ProvisioningState `protobuf:"varint,5,opt,name=provisioning_state,json=provisioningState,proto3,enum=teleport.provisioning.v1.ProvisioningState" json:"provisioning_state,omitempty"`
	// ExternalID holds the ID used by the downstream system to represent this
	// principal
	ExternalId string `protobuf:"bytes,2,opt,name=external_id,json=externalId,proto3" json:"external_id,omitempty"`
	// LastProvisioned records the last time this record was provisioined into
	// the downstream system.
	LastProvisioned *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=last_provisioned,json=lastProvisioned,proto3" json:"last_provisioned,omitempty"`
	// Error holds a description of the last provisioing error, if any.
	Error string `protobuf:"bytes,4,opt,name=error,proto3" json:"error,omitempty"`
	// Revision holds the revision of the principal record provisioned into the
	// downstream system. Used to assert that the latest revision of the principal
	// is provisioned downstream and detect changes in the principal that require
	// re-provisoning.
	ProvisionedPrincipalRevision string `protobuf:"bytes,6,opt,name=provisioned_principal_revision,json=provisionedPrincipalRevision,proto3" json:"provisioned_principal_revision,omitempty"`
	// ActiveLocks holds the list of known active locks on the principal. Used to
	// store the lock state across restarts of Teleport in order to detect state
	// changes that may happen while Teleport is not running (e.g. a storage
	// backend deleting an expired lock record while Teleport is offline)
	ActiveLocks []string `protobuf:"bytes,7,rep,name=active_locks,json=activeLocks,proto3" json:"active_locks,omitempty"`
}

func (x *PrincipalStateStatus) Reset() {
	*x = PrincipalStateStatus{}
	mi := &file_teleport_provisioning_v1_provisioning_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PrincipalStateStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PrincipalStateStatus) ProtoMessage() {}

func (x *PrincipalStateStatus) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_provisioning_v1_provisioning_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PrincipalStateStatus.ProtoReflect.Descriptor instead.
func (*PrincipalStateStatus) Descriptor() ([]byte, []int) {
	return file_teleport_provisioning_v1_provisioning_proto_rawDescGZIP(), []int{2}
}

func (x *PrincipalStateStatus) GetProvisioningState() ProvisioningState {
	if x != nil {
		return x.ProvisioningState
	}
	return ProvisioningState_PROVISIONING_STATE_UNSPECIFIED
}

func (x *PrincipalStateStatus) GetExternalId() string {
	if x != nil {
		return x.ExternalId
	}
	return ""
}

func (x *PrincipalStateStatus) GetLastProvisioned() *timestamppb.Timestamp {
	if x != nil {
		return x.LastProvisioned
	}
	return nil
}

func (x *PrincipalStateStatus) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

func (x *PrincipalStateStatus) GetProvisionedPrincipalRevision() string {
	if x != nil {
		return x.ProvisionedPrincipalRevision
	}
	return ""
}

func (x *PrincipalStateStatus) GetActiveLocks() []string {
	if x != nil {
		return x.ActiveLocks
	}
	return nil
}

var File_teleport_provisioning_v1_provisioning_proto protoreflect.FileDescriptor

var file_teleport_provisioning_v1_provisioning_proto_rawDesc = []byte{
	0x0a, 0x2b, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x18, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f,
	0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9d, 0x02, 0x0a, 0x0e,
	0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x12,
	0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6b, 0x69,
	0x6e, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x4b, 0x69, 0x6e, 0x64, 0x12, 0x18, 0x0a,
	0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x38, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x12, 0x40, 0x0a, 0x04, 0x73, 0x70, 0x65, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x61, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x53, 0x70, 0x65, 0x63, 0x52, 0x04, 0x73,
	0x70, 0x65, 0x63, 0x12, 0x46, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x50,
	0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0xac, 0x01, 0x0a, 0x12,
	0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x53, 0x70,
	0x65, 0x63, 0x12, 0x23, 0x0a, 0x0d, 0x64, 0x6f, 0x77, 0x6e, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x64, 0x6f, 0x77, 0x6e, 0x73,
	0x74, 0x72, 0x65, 0x61, 0x6d, 0x49, 0x64, 0x12, 0x4e, 0x0a, 0x0e, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x61, 0x6c, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x61, 0x6c, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0d, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69,
	0x70, 0x61, 0x6c, 0x54, 0x79, 0x70, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x61, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x70,
	0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x49, 0x64, 0x22, 0xe7, 0x02, 0x0a, 0x14, 0x50,
	0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x12, 0x5a, 0x0a, 0x12, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e,
	0x69, 0x6e, 0x67, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x76, 0x69,
	0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x11, 0x70, 0x72,
	0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12,
	0x1f, 0x0a, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x49, 0x64,
	0x12, 0x45, 0x0a, 0x10, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69,
	0x6f, 0x6e, 0x65, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0f, 0x6c, 0x61, 0x73, 0x74, 0x50, 0x72, 0x6f, 0x76,
	0x69, 0x73, 0x69, 0x6f, 0x6e, 0x65, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x44, 0x0a,
	0x1e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x65, 0x64, 0x5f, 0x70, 0x72, 0x69,
	0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x5f, 0x72, 0x65, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x1c, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e,
	0x65, 0x64, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x52, 0x65, 0x76, 0x69, 0x73,
	0x69, 0x6f, 0x6e, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x6c, 0x6f,
	0x63, 0x6b, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x74, 0x69, 0x76,
	0x65, 0x4c, 0x6f, 0x63, 0x6b, 0x73, 0x4a, 0x04, 0x08, 0x01, 0x10, 0x02, 0x52, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x2a, 0x99, 0x01, 0x0a, 0x11, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69,
	0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x22, 0x0a, 0x1e, 0x50, 0x52,
	0x4f, 0x56, 0x49, 0x53, 0x49, 0x4f, 0x4e, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45,
	0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1c,
	0x0a, 0x18, 0x50, 0x52, 0x4f, 0x56, 0x49, 0x53, 0x49, 0x4f, 0x4e, 0x49, 0x4e, 0x47, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x53, 0x54, 0x41, 0x4c, 0x45, 0x10, 0x01, 0x12, 0x22, 0x0a, 0x1e,
	0x50, 0x52, 0x4f, 0x56, 0x49, 0x53, 0x49, 0x4f, 0x4e, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x50, 0x52, 0x4f, 0x56, 0x49, 0x53, 0x49, 0x4f, 0x4e, 0x45, 0x44, 0x10, 0x02,
	0x12, 0x1e, 0x0a, 0x1a, 0x50, 0x52, 0x4f, 0x56, 0x49, 0x53, 0x49, 0x4f, 0x4e, 0x49, 0x4e, 0x47,
	0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x45, 0x4c, 0x45, 0x54, 0x45, 0x44, 0x10, 0x03,
	0x2a, 0x68, 0x0a, 0x0d, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x1e, 0x0a, 0x1a, 0x50, 0x52, 0x49, 0x4e, 0x43, 0x49, 0x50, 0x41, 0x4c, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10,
	0x00, 0x12, 0x17, 0x0a, 0x13, 0x50, 0x52, 0x49, 0x4e, 0x43, 0x49, 0x50, 0x41, 0x4c, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x5f, 0x55, 0x53, 0x45, 0x52, 0x10, 0x01, 0x12, 0x1e, 0x0a, 0x1a, 0x50, 0x52,
	0x49, 0x4e, 0x43, 0x49, 0x50, 0x41, 0x4c, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x41, 0x43, 0x43,
	0x45, 0x53, 0x53, 0x5f, 0x4c, 0x49, 0x53, 0x54, 0x10, 0x02, 0x42, 0x5c, 0x5a, 0x5a, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f,
	0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73,
	0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2f, 0x76, 0x31, 0x3b, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73,
	0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_provisioning_v1_provisioning_proto_rawDescOnce sync.Once
	file_teleport_provisioning_v1_provisioning_proto_rawDescData = file_teleport_provisioning_v1_provisioning_proto_rawDesc
)

func file_teleport_provisioning_v1_provisioning_proto_rawDescGZIP() []byte {
	file_teleport_provisioning_v1_provisioning_proto_rawDescOnce.Do(func() {
		file_teleport_provisioning_v1_provisioning_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_provisioning_v1_provisioning_proto_rawDescData)
	})
	return file_teleport_provisioning_v1_provisioning_proto_rawDescData
}

var file_teleport_provisioning_v1_provisioning_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_teleport_provisioning_v1_provisioning_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_teleport_provisioning_v1_provisioning_proto_goTypes = []any{
	(ProvisioningState)(0),        // 0: teleport.provisioning.v1.ProvisioningState
	(PrincipalType)(0),            // 1: teleport.provisioning.v1.PrincipalType
	(*PrincipalState)(nil),        // 2: teleport.provisioning.v1.PrincipalState
	(*PrincipalStateSpec)(nil),    // 3: teleport.provisioning.v1.PrincipalStateSpec
	(*PrincipalStateStatus)(nil),  // 4: teleport.provisioning.v1.PrincipalStateStatus
	(*v1.Metadata)(nil),           // 5: teleport.header.v1.Metadata
	(*timestamppb.Timestamp)(nil), // 6: google.protobuf.Timestamp
}
var file_teleport_provisioning_v1_provisioning_proto_depIdxs = []int32{
	5, // 0: teleport.provisioning.v1.PrincipalState.metadata:type_name -> teleport.header.v1.Metadata
	3, // 1: teleport.provisioning.v1.PrincipalState.spec:type_name -> teleport.provisioning.v1.PrincipalStateSpec
	4, // 2: teleport.provisioning.v1.PrincipalState.status:type_name -> teleport.provisioning.v1.PrincipalStateStatus
	1, // 3: teleport.provisioning.v1.PrincipalStateSpec.principal_type:type_name -> teleport.provisioning.v1.PrincipalType
	0, // 4: teleport.provisioning.v1.PrincipalStateStatus.provisioning_state:type_name -> teleport.provisioning.v1.ProvisioningState
	6, // 5: teleport.provisioning.v1.PrincipalStateStatus.last_provisioned:type_name -> google.protobuf.Timestamp
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_teleport_provisioning_v1_provisioning_proto_init() }
func file_teleport_provisioning_v1_provisioning_proto_init() {
	if File_teleport_provisioning_v1_provisioning_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_provisioning_v1_provisioning_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_provisioning_v1_provisioning_proto_goTypes,
		DependencyIndexes: file_teleport_provisioning_v1_provisioning_proto_depIdxs,
		EnumInfos:         file_teleport_provisioning_v1_provisioning_proto_enumTypes,
		MessageInfos:      file_teleport_provisioning_v1_provisioning_proto_msgTypes,
	}.Build()
	File_teleport_provisioning_v1_provisioning_proto = out.File
	file_teleport_provisioning_v1_provisioning_proto_rawDesc = nil
	file_teleport_provisioning_v1_provisioning_proto_goTypes = nil
	file_teleport_provisioning_v1_provisioning_proto_depIdxs = nil
}