//*
// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        (unknown)
// source: teleport/dynamicwindows/v1/dynamicwindows_service.proto

package dynamicwindowsv1

import (
	types "github.com/gravitational/teleport/api/types"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// ListDynamicWindowsDesktopsRequest is request to fetch single page of dynamic Windows desktops
type ListDynamicWindowsDesktopsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The maximum number of items to return.
	// The server may impose a different page size at its discretion.
	PageSize int32 `protobuf:"varint,1,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// The next_page_token value returned from a previous List request, if any.
	PageToken string `protobuf:"bytes,2,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
}

func (x *ListDynamicWindowsDesktopsRequest) Reset() {
	*x = ListDynamicWindowsDesktopsRequest{}
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListDynamicWindowsDesktopsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListDynamicWindowsDesktopsRequest) ProtoMessage() {}

func (x *ListDynamicWindowsDesktopsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListDynamicWindowsDesktopsRequest.ProtoReflect.Descriptor instead.
func (*ListDynamicWindowsDesktopsRequest) Descriptor() ([]byte, []int) {
	return file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescGZIP(), []int{0}
}

func (x *ListDynamicWindowsDesktopsRequest) GetPageSize() int32 {
	if x != nil {
		return x.PageSize
	}
	return 0
}

func (x *ListDynamicWindowsDesktopsRequest) GetPageToken() string {
	if x != nil {
		return x.PageToken
	}
	return ""
}

// ListDynamicWindowsDesktopsRequest is single page of dynamic Windows desktops
type ListDynamicWindowsDesktopsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The page of DynamicWindowsDesktops that matched the request.
	Desktops []*types.DynamicWindowsDesktopV1 `protobuf:"bytes,1,rep,name=desktops,proto3" json:"desktops,omitempty"`
	// Token to retrieve the next page of results, or empty if there are no
	// more results in the list.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
}

func (x *ListDynamicWindowsDesktopsResponse) Reset() {
	*x = ListDynamicWindowsDesktopsResponse{}
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListDynamicWindowsDesktopsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListDynamicWindowsDesktopsResponse) ProtoMessage() {}

func (x *ListDynamicWindowsDesktopsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListDynamicWindowsDesktopsResponse.ProtoReflect.Descriptor instead.
func (*ListDynamicWindowsDesktopsResponse) Descriptor() ([]byte, []int) {
	return file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescGZIP(), []int{1}
}

func (x *ListDynamicWindowsDesktopsResponse) GetDesktops() []*types.DynamicWindowsDesktopV1 {
	if x != nil {
		return x.Desktops
	}
	return nil
}

func (x *ListDynamicWindowsDesktopsResponse) GetNextPageToken() string {
	if x != nil {
		return x.NextPageToken
	}
	return ""
}

// GetDynamicWindowsDesktopRequest is a request for a specific dynamic Windows desktop.
type GetDynamicWindowsDesktopRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name is the name of the dynamic Windows desktop to be requested.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *GetDynamicWindowsDesktopRequest) Reset() {
	*x = GetDynamicWindowsDesktopRequest{}
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetDynamicWindowsDesktopRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetDynamicWindowsDesktopRequest) ProtoMessage() {}

func (x *GetDynamicWindowsDesktopRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetDynamicWindowsDesktopRequest.ProtoReflect.Descriptor instead.
func (*GetDynamicWindowsDesktopRequest) Descriptor() ([]byte, []int) {
	return file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescGZIP(), []int{2}
}

func (x *GetDynamicWindowsDesktopRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// CreateDynamicWindowsDesktopRequest is a request for a specific dynamic Windows desktop.
type CreateDynamicWindowsDesktopRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// desktop to be created
	Desktop *types.DynamicWindowsDesktopV1 `protobuf:"bytes,1,opt,name=desktop,proto3" json:"desktop,omitempty"`
}

func (x *CreateDynamicWindowsDesktopRequest) Reset() {
	*x = CreateDynamicWindowsDesktopRequest{}
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CreateDynamicWindowsDesktopRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateDynamicWindowsDesktopRequest) ProtoMessage() {}

func (x *CreateDynamicWindowsDesktopRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateDynamicWindowsDesktopRequest.ProtoReflect.Descriptor instead.
func (*CreateDynamicWindowsDesktopRequest) Descriptor() ([]byte, []int) {
	return file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescGZIP(), []int{3}
}

func (x *CreateDynamicWindowsDesktopRequest) GetDesktop() *types.DynamicWindowsDesktopV1 {
	if x != nil {
		return x.Desktop
	}
	return nil
}

// UpdateDynamicWindowsDesktopRequest is a request for a specific dynamic Windows desktop.
type UpdateDynamicWindowsDesktopRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// desktop to be updated
	Desktop *types.DynamicWindowsDesktopV1 `protobuf:"bytes,1,opt,name=desktop,proto3" json:"desktop,omitempty"`
}

func (x *UpdateDynamicWindowsDesktopRequest) Reset() {
	*x = UpdateDynamicWindowsDesktopRequest{}
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UpdateDynamicWindowsDesktopRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateDynamicWindowsDesktopRequest) ProtoMessage() {}

func (x *UpdateDynamicWindowsDesktopRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateDynamicWindowsDesktopRequest.ProtoReflect.Descriptor instead.
func (*UpdateDynamicWindowsDesktopRequest) Descriptor() ([]byte, []int) {
	return file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescGZIP(), []int{4}
}

func (x *UpdateDynamicWindowsDesktopRequest) GetDesktop() *types.DynamicWindowsDesktopV1 {
	if x != nil {
		return x.Desktop
	}
	return nil
}

// DeleteDynamicWindowsDesktopRequest is a request to delete a Windows desktop host.
type DeleteDynamicWindowsDesktopRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name is the name of the Windows desktop host.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DeleteDynamicWindowsDesktopRequest) Reset() {
	*x = DeleteDynamicWindowsDesktopRequest{}
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DeleteDynamicWindowsDesktopRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteDynamicWindowsDesktopRequest) ProtoMessage() {}

func (x *DeleteDynamicWindowsDesktopRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteDynamicWindowsDesktopRequest.ProtoReflect.Descriptor instead.
func (*DeleteDynamicWindowsDesktopRequest) Descriptor() ([]byte, []int) {
	return file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescGZIP(), []int{5}
}

func (x *DeleteDynamicWindowsDesktopRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_teleport_dynamicwindows_v1_dynamicwindows_service_proto protoreflect.FileDescriptor

var file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDesc = []byte{
	0x0a, 0x37, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x79, 0x6e, 0x61, 0x6d,
	0x69, 0x63, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x64, 0x79, 0x6e,
	0x61, 0x6d, 0x69, 0x63, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x77, 0x69, 0x6e, 0x64, 0x6f,
	0x77, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x65, 0x67,
	0x61, 0x63, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5f, 0x0a, 0x21, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x79, 0x6e,
	0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74,
	0x6f, 0x70, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x61,
	0x67, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x70,
	0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61, 0x67, 0x65, 0x5f,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x61, 0x67,
	0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x88, 0x01, 0x0a, 0x22, 0x4c, 0x69, 0x73, 0x74, 0x44,
	0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73,
	0x6b, 0x74, 0x6f, 0x70, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3a, 0x0a,
	0x08, 0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1e, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57,
	0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x56, 0x31, 0x52,
	0x08, 0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x73, 0x12, 0x26, 0x0a, 0x0f, 0x6e, 0x65, 0x78,
	0x74, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0d, 0x6e, 0x65, 0x78, 0x74, 0x50, 0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x22, 0x35, 0x0a, 0x1f, 0x47, 0x65, 0x74, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57,
	0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x5e, 0x0a, 0x22, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
	0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x38,
	0x0a, 0x07, 0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1e, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57,
	0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x56, 0x31, 0x52,
	0x07, 0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x22, 0x5e, 0x0a, 0x22, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
	0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x38,
	0x0a, 0x07, 0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1e, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57,
	0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x56, 0x31, 0x52,
	0x07, 0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x22, 0x38, 0x0a, 0x22, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
	0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x32, 0xa3, 0x05, 0x0a, 0x15, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69,
	0x6e, 0x64, 0x6f, 0x77, 0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x9b, 0x01, 0x0a,
	0x1a, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64,
	0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x73, 0x12, 0x3d, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x77, 0x69,
	0x6e, 0x64, 0x6f, 0x77, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x79, 0x6e,
	0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74,
	0x6f, 0x70, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x3e, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x77, 0x69, 0x6e,
	0x64, 0x6f, 0x77, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x79, 0x6e, 0x61,
	0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f,
	0x70, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x77, 0x0a, 0x18, 0x47, 0x65,
	0x74, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44,
	0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x12, 0x3b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69,
	0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x79, 0x6e, 0x61,
	0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f,
	0x70, 0x56, 0x31, 0x12, 0x7d, 0x0a, 0x1b, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x44, 0x79, 0x6e,
	0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74,
	0x6f, 0x70, 0x12, 0x3e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x79,
	0x6e, 0x61, 0x6d, 0x69, 0x63, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e,
	0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x79, 0x6e, 0x61, 0x6d,
	0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70,
	0x56, 0x31, 0x12, 0x7d, 0x0a, 0x1b, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x44, 0x79, 0x6e, 0x61,
	0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f,
	0x70, 0x12, 0x3e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x79, 0x6e,
	0x61, 0x6d, 0x69, 0x63, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64,
	0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x1e, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69,
	0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x56,
	0x31, 0x12, 0x75, 0x0a, 0x1b, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x44, 0x79, 0x6e, 0x61, 0x6d,
	0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70,
	0x12, 0x3e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x79, 0x6e, 0x61,
	0x6d, 0x69, 0x63, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x57, 0x69, 0x6e, 0x64, 0x6f,
	0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42, 0x60, 0x5a, 0x5e, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70,
	0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x77,
	0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x2f, 0x76, 0x31, 0x3b, 0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69,
	0x63, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescOnce sync.Once
	file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescData = file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDesc
)

func file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescGZIP() []byte {
	file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescOnce.Do(func() {
		file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescData)
	})
	return file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDescData
}

var file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_goTypes = []any{
	(*ListDynamicWindowsDesktopsRequest)(nil),  // 0: teleport.dynamicwindows.v1.ListDynamicWindowsDesktopsRequest
	(*ListDynamicWindowsDesktopsResponse)(nil), // 1: teleport.dynamicwindows.v1.ListDynamicWindowsDesktopsResponse
	(*GetDynamicWindowsDesktopRequest)(nil),    // 2: teleport.dynamicwindows.v1.GetDynamicWindowsDesktopRequest
	(*CreateDynamicWindowsDesktopRequest)(nil), // 3: teleport.dynamicwindows.v1.CreateDynamicWindowsDesktopRequest
	(*UpdateDynamicWindowsDesktopRequest)(nil), // 4: teleport.dynamicwindows.v1.UpdateDynamicWindowsDesktopRequest
	(*DeleteDynamicWindowsDesktopRequest)(nil), // 5: teleport.dynamicwindows.v1.DeleteDynamicWindowsDesktopRequest
	(*types.DynamicWindowsDesktopV1)(nil),      // 6: types.DynamicWindowsDesktopV1
	(*emptypb.Empty)(nil),                      // 7: google.protobuf.Empty
}
var file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_depIdxs = []int32{
	6, // 0: teleport.dynamicwindows.v1.ListDynamicWindowsDesktopsResponse.desktops:type_name -> types.DynamicWindowsDesktopV1
	6, // 1: teleport.dynamicwindows.v1.CreateDynamicWindowsDesktopRequest.desktop:type_name -> types.DynamicWindowsDesktopV1
	6, // 2: teleport.dynamicwindows.v1.UpdateDynamicWindowsDesktopRequest.desktop:type_name -> types.DynamicWindowsDesktopV1
	0, // 3: teleport.dynamicwindows.v1.DynamicWindowsService.ListDynamicWindowsDesktops:input_type -> teleport.dynamicwindows.v1.ListDynamicWindowsDesktopsRequest
	2, // 4: teleport.dynamicwindows.v1.DynamicWindowsService.GetDynamicWindowsDesktop:input_type -> teleport.dynamicwindows.v1.GetDynamicWindowsDesktopRequest
	3, // 5: teleport.dynamicwindows.v1.DynamicWindowsService.CreateDynamicWindowsDesktop:input_type -> teleport.dynamicwindows.v1.CreateDynamicWindowsDesktopRequest
	4, // 6: teleport.dynamicwindows.v1.DynamicWindowsService.UpdateDynamicWindowsDesktop:input_type -> teleport.dynamicwindows.v1.UpdateDynamicWindowsDesktopRequest
	5, // 7: teleport.dynamicwindows.v1.DynamicWindowsService.DeleteDynamicWindowsDesktop:input_type -> teleport.dynamicwindows.v1.DeleteDynamicWindowsDesktopRequest
	1, // 8: teleport.dynamicwindows.v1.DynamicWindowsService.ListDynamicWindowsDesktops:output_type -> teleport.dynamicwindows.v1.ListDynamicWindowsDesktopsResponse
	6, // 9: teleport.dynamicwindows.v1.DynamicWindowsService.GetDynamicWindowsDesktop:output_type -> types.DynamicWindowsDesktopV1
	6, // 10: teleport.dynamicwindows.v1.DynamicWindowsService.CreateDynamicWindowsDesktop:output_type -> types.DynamicWindowsDesktopV1
	6, // 11: teleport.dynamicwindows.v1.DynamicWindowsService.UpdateDynamicWindowsDesktop:output_type -> types.DynamicWindowsDesktopV1
	7, // 12: teleport.dynamicwindows.v1.DynamicWindowsService.DeleteDynamicWindowsDesktop:output_type -> google.protobuf.Empty
	8, // [8:13] is the sub-list for method output_type
	3, // [3:8] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_init() }
func file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_init() {
	if File_teleport_dynamicwindows_v1_dynamicwindows_service_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_goTypes,
		DependencyIndexes: file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_depIdxs,
		MessageInfos:      file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_msgTypes,
	}.Build()
	File_teleport_dynamicwindows_v1_dynamicwindows_service_proto = out.File
	file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_rawDesc = nil
	file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_goTypes = nil
	file_teleport_dynamicwindows_v1_dynamicwindows_service_proto_depIdxs = nil
}
