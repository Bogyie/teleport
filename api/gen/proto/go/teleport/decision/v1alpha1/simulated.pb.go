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
// 	protoc-gen-go v1.36.1
// 	protoc        (unknown)
// source: teleport/decision/v1alpha1/simulated.proto

package decisionpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// GetSimulatedTLSIdentityRequest is used to request a TLS identity object based on a target user. The resulting
// identity object is not authoratative, and is meant for use only in the context of auditing and introspection.
type GetSimulatedTLSIdentityRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Username is the teleport username of the target user.
	Username      string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetSimulatedTLSIdentityRequest) Reset() {
	*x = GetSimulatedTLSIdentityRequest{}
	mi := &file_teleport_decision_v1alpha1_simulated_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetSimulatedTLSIdentityRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSimulatedTLSIdentityRequest) ProtoMessage() {}

func (x *GetSimulatedTLSIdentityRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_simulated_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSimulatedTLSIdentityRequest.ProtoReflect.Descriptor instead.
func (*GetSimulatedTLSIdentityRequest) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_simulated_proto_rawDescGZIP(), []int{0}
}

func (x *GetSimulatedTLSIdentityRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

// GetSimulatedTLSIdentityResponse is used to return a TLS identity object based on a target user. The resulting
// identity object is not authoratative, and is meant for use only in the context of auditing and introspection.
type GetSimulatedTLSIdentityResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// TlsIdentity is a simulated TLS identity object.
	TlsIdentity   *TLSIdentity `protobuf:"bytes,1,opt,name=tls_identity,json=tlsIdentity,proto3" json:"tls_identity,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetSimulatedTLSIdentityResponse) Reset() {
	*x = GetSimulatedTLSIdentityResponse{}
	mi := &file_teleport_decision_v1alpha1_simulated_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetSimulatedTLSIdentityResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSimulatedTLSIdentityResponse) ProtoMessage() {}

func (x *GetSimulatedTLSIdentityResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_simulated_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSimulatedTLSIdentityResponse.ProtoReflect.Descriptor instead.
func (*GetSimulatedTLSIdentityResponse) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_simulated_proto_rawDescGZIP(), []int{1}
}

func (x *GetSimulatedTLSIdentityResponse) GetTlsIdentity() *TLSIdentity {
	if x != nil {
		return x.TlsIdentity
	}
	return nil
}

// GetSimulatedSSHIdentityRequest is used to request a SSH identity object based on a target user. The resulting
// identity object is not authoratative, and is meant for use only in the context of auditing and introspection.
type GetSimulatedSSHIdentityRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Username is the teleport username of the target user.
	Username      string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetSimulatedSSHIdentityRequest) Reset() {
	*x = GetSimulatedSSHIdentityRequest{}
	mi := &file_teleport_decision_v1alpha1_simulated_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetSimulatedSSHIdentityRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSimulatedSSHIdentityRequest) ProtoMessage() {}

func (x *GetSimulatedSSHIdentityRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_simulated_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSimulatedSSHIdentityRequest.ProtoReflect.Descriptor instead.
func (*GetSimulatedSSHIdentityRequest) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_simulated_proto_rawDescGZIP(), []int{2}
}

func (x *GetSimulatedSSHIdentityRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

// GetSimulatedSSHIdentityResponse is used to return a SSH identity object based on a target user. The resulting
// identity object is not authoratative, and is meant for use only in the context of auditing and introspection.
type GetSimulatedSSHIdentityResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// SshIdentity is a simulated SSH identity object.
	SshIdentity   *SSHIdentity `protobuf:"bytes,1,opt,name=ssh_identity,json=sshIdentity,proto3" json:"ssh_identity,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetSimulatedSSHIdentityResponse) Reset() {
	*x = GetSimulatedSSHIdentityResponse{}
	mi := &file_teleport_decision_v1alpha1_simulated_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetSimulatedSSHIdentityResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSimulatedSSHIdentityResponse) ProtoMessage() {}

func (x *GetSimulatedSSHIdentityResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_simulated_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSimulatedSSHIdentityResponse.ProtoReflect.Descriptor instead.
func (*GetSimulatedSSHIdentityResponse) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_simulated_proto_rawDescGZIP(), []int{3}
}

func (x *GetSimulatedSSHIdentityResponse) GetSshIdentity() *SSHIdentity {
	if x != nil {
		return x.SshIdentity
	}
	return nil
}

var File_teleport_decision_v1alpha1_simulated_proto protoreflect.FileDescriptor

var file_teleport_decision_v1alpha1_simulated_proto_rawDesc = []byte{
	0x0a, 0x2a, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x63, 0x69, 0x73,
	0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x73, 0x69, 0x6d,
	0x75, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x1a, 0x2d, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2f, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x31, 0x2f, 0x73, 0x73, 0x68, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2d, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2f, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x31, 0x2f, 0x74, 0x6c, 0x73, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x3c, 0x0a, 0x1e, 0x47, 0x65, 0x74, 0x53, 0x69, 0x6d,
	0x75, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x54, 0x4c, 0x53, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72,
	0x6e, 0x61, 0x6d, 0x65, 0x22, 0x6d, 0x0a, 0x1f, 0x47, 0x65, 0x74, 0x53, 0x69, 0x6d, 0x75, 0x6c,
	0x61, 0x74, 0x65, 0x64, 0x54, 0x4c, 0x53, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4a, 0x0a, 0x0c, 0x74, 0x6c, 0x73, 0x5f, 0x69,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x54, 0x4c, 0x53, 0x49, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x0b, 0x74, 0x6c, 0x73, 0x49, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x22, 0x3c, 0x0a, 0x1e, 0x47, 0x65, 0x74, 0x53, 0x69, 0x6d, 0x75, 0x6c, 0x61,
	0x74, 0x65, 0x64, 0x53, 0x53, 0x48, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x22, 0x6d, 0x0a, 0x1f, 0x47, 0x65, 0x74, 0x53, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x65,
	0x64, 0x53, 0x53, 0x48, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4a, 0x0a, 0x0c, 0x73, 0x73, 0x68, 0x5f, 0x69, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x53, 0x53, 0x48, 0x49, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x52, 0x0b, 0x73, 0x73, 0x68, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x42, 0x5a, 0x5a, 0x58, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
	0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f,
	0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x31, 0x3b, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_decision_v1alpha1_simulated_proto_rawDescOnce sync.Once
	file_teleport_decision_v1alpha1_simulated_proto_rawDescData = file_teleport_decision_v1alpha1_simulated_proto_rawDesc
)

func file_teleport_decision_v1alpha1_simulated_proto_rawDescGZIP() []byte {
	file_teleport_decision_v1alpha1_simulated_proto_rawDescOnce.Do(func() {
		file_teleport_decision_v1alpha1_simulated_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_decision_v1alpha1_simulated_proto_rawDescData)
	})
	return file_teleport_decision_v1alpha1_simulated_proto_rawDescData
}

var file_teleport_decision_v1alpha1_simulated_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_teleport_decision_v1alpha1_simulated_proto_goTypes = []any{
	(*GetSimulatedTLSIdentityRequest)(nil),  // 0: teleport.decision.v1alpha1.GetSimulatedTLSIdentityRequest
	(*GetSimulatedTLSIdentityResponse)(nil), // 1: teleport.decision.v1alpha1.GetSimulatedTLSIdentityResponse
	(*GetSimulatedSSHIdentityRequest)(nil),  // 2: teleport.decision.v1alpha1.GetSimulatedSSHIdentityRequest
	(*GetSimulatedSSHIdentityResponse)(nil), // 3: teleport.decision.v1alpha1.GetSimulatedSSHIdentityResponse
	(*TLSIdentity)(nil),                     // 4: teleport.decision.v1alpha1.TLSIdentity
	(*SSHIdentity)(nil),                     // 5: teleport.decision.v1alpha1.SSHIdentity
}
var file_teleport_decision_v1alpha1_simulated_proto_depIdxs = []int32{
	4, // 0: teleport.decision.v1alpha1.GetSimulatedTLSIdentityResponse.tls_identity:type_name -> teleport.decision.v1alpha1.TLSIdentity
	5, // 1: teleport.decision.v1alpha1.GetSimulatedSSHIdentityResponse.ssh_identity:type_name -> teleport.decision.v1alpha1.SSHIdentity
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_teleport_decision_v1alpha1_simulated_proto_init() }
func file_teleport_decision_v1alpha1_simulated_proto_init() {
	if File_teleport_decision_v1alpha1_simulated_proto != nil {
		return
	}
	file_teleport_decision_v1alpha1_ssh_identity_proto_init()
	file_teleport_decision_v1alpha1_tls_identity_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_decision_v1alpha1_simulated_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_decision_v1alpha1_simulated_proto_goTypes,
		DependencyIndexes: file_teleport_decision_v1alpha1_simulated_proto_depIdxs,
		MessageInfos:      file_teleport_decision_v1alpha1_simulated_proto_msgTypes,
	}.Build()
	File_teleport_decision_v1alpha1_simulated_proto = out.File
	file_teleport_decision_v1alpha1_simulated_proto_rawDesc = nil
	file_teleport_decision_v1alpha1_simulated_proto_goTypes = nil
	file_teleport_decision_v1alpha1_simulated_proto_depIdxs = nil
}
