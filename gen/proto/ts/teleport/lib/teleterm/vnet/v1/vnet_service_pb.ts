/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/lib/teleterm/vnet/v1/vnet_service.proto" (package "teleport.lib.teleterm.vnet.v1", syntax proto3)
// tslint:disable
// @ts-nocheck
//
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
//
import { ServiceType } from "@protobuf-ts/runtime-rpc";
import { WireType } from "@protobuf-ts/runtime";
import type { BinaryWriteOptions } from "@protobuf-ts/runtime";
import type { IBinaryWriter } from "@protobuf-ts/runtime";
import { UnknownFieldHandler } from "@protobuf-ts/runtime";
import type { BinaryReadOptions } from "@protobuf-ts/runtime";
import type { IBinaryReader } from "@protobuf-ts/runtime";
import type { PartialMessage } from "@protobuf-ts/runtime";
import { reflectionMergePartial } from "@protobuf-ts/runtime";
import { MessageType } from "@protobuf-ts/runtime";
/**
 * Request for Start.
 *
 * @generated from protobuf message teleport.lib.teleterm.vnet.v1.StartRequest
 */
export interface StartRequest {
}
/**
 * Response for Start.
 *
 * @generated from protobuf message teleport.lib.teleterm.vnet.v1.StartResponse
 */
export interface StartResponse {
}
/**
 * Request for Stop.
 *
 * @generated from protobuf message teleport.lib.teleterm.vnet.v1.StopRequest
 */
export interface StopRequest {
}
/**
 * Response for Stop.
 *
 * @generated from protobuf message teleport.lib.teleterm.vnet.v1.StopResponse
 */
export interface StopResponse {
}
/**
 * Request for ListDNSZones.
 *
 * @generated from protobuf message teleport.lib.teleterm.vnet.v1.ListDNSZonesRequest
 */
export interface ListDNSZonesRequest {
}
/**
 * Response for ListDNSZones.
 *
 * @generated from protobuf message teleport.lib.teleterm.vnet.v1.ListDNSZonesResponse
 */
export interface ListDNSZonesResponse {
    /**
     * dns_zones is a deduplicated list of DNS zones.
     *
     * @generated from protobuf field: repeated string dns_zones = 1;
     */
    dnsZones: string[];
}
/**
 * Request for GetBackgroundItemStatus.
 *
 * @generated from protobuf message teleport.lib.teleterm.vnet.v1.GetBackgroundItemStatusRequest
 */
export interface GetBackgroundItemStatusRequest {
}
/**
 * Response for GetBackgroundItemStatus.
 *
 * @generated from protobuf message teleport.lib.teleterm.vnet.v1.GetBackgroundItemStatusResponse
 */
export interface GetBackgroundItemStatusResponse {
    /**
     * @generated from protobuf field: teleport.lib.teleterm.vnet.v1.BackgroundItemStatus status = 1;
     */
    status: BackgroundItemStatus;
}
/**
 * BackgroundItemStatus maps to SMAppServiceStatus of the Service Management framework in macOS.
 * https://developer.apple.com/documentation/servicemanagement/smappservice/status-swift.enum?language=objc
 *
 * @generated from protobuf enum teleport.lib.teleterm.vnet.v1.BackgroundItemStatus
 */
export enum BackgroundItemStatus {
    /**
     * @generated from protobuf enum value: BACKGROUND_ITEM_STATUS_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * @generated from protobuf enum value: BACKGROUND_ITEM_STATUS_NOT_REGISTERED = 1;
     */
    NOT_REGISTERED = 1,
    /**
     * This is the status the background item should have before tsh attempts to send a message to the
     * daemon.
     *
     * @generated from protobuf enum value: BACKGROUND_ITEM_STATUS_ENABLED = 2;
     */
    ENABLED = 2,
    /**
     * @generated from protobuf enum value: BACKGROUND_ITEM_STATUS_REQUIRES_APPROVAL = 3;
     */
    REQUIRES_APPROVAL = 3,
    /**
     * @generated from protobuf enum value: BACKGROUND_ITEM_STATUS_NOT_FOUND = 4;
     */
    NOT_FOUND = 4,
    /**
     * @generated from protobuf enum value: BACKGROUND_ITEM_STATUS_NOT_SUPPORTED = 5;
     */
    NOT_SUPPORTED = 5
}
// @generated message type with reflection information, may provide speed optimized methods
class StartRequest$Type extends MessageType<StartRequest> {
    constructor() {
        super("teleport.lib.teleterm.vnet.v1.StartRequest", []);
    }
    create(value?: PartialMessage<StartRequest>): StartRequest {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<StartRequest>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: StartRequest): StartRequest {
        return target ?? this.create();
    }
    internalBinaryWrite(message: StartRequest, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.vnet.v1.StartRequest
 */
export const StartRequest = new StartRequest$Type();
// @generated message type with reflection information, may provide speed optimized methods
class StartResponse$Type extends MessageType<StartResponse> {
    constructor() {
        super("teleport.lib.teleterm.vnet.v1.StartResponse", []);
    }
    create(value?: PartialMessage<StartResponse>): StartResponse {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<StartResponse>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: StartResponse): StartResponse {
        return target ?? this.create();
    }
    internalBinaryWrite(message: StartResponse, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.vnet.v1.StartResponse
 */
export const StartResponse = new StartResponse$Type();
// @generated message type with reflection information, may provide speed optimized methods
class StopRequest$Type extends MessageType<StopRequest> {
    constructor() {
        super("teleport.lib.teleterm.vnet.v1.StopRequest", []);
    }
    create(value?: PartialMessage<StopRequest>): StopRequest {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<StopRequest>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: StopRequest): StopRequest {
        return target ?? this.create();
    }
    internalBinaryWrite(message: StopRequest, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.vnet.v1.StopRequest
 */
export const StopRequest = new StopRequest$Type();
// @generated message type with reflection information, may provide speed optimized methods
class StopResponse$Type extends MessageType<StopResponse> {
    constructor() {
        super("teleport.lib.teleterm.vnet.v1.StopResponse", []);
    }
    create(value?: PartialMessage<StopResponse>): StopResponse {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<StopResponse>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: StopResponse): StopResponse {
        return target ?? this.create();
    }
    internalBinaryWrite(message: StopResponse, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.vnet.v1.StopResponse
 */
export const StopResponse = new StopResponse$Type();
// @generated message type with reflection information, may provide speed optimized methods
class ListDNSZonesRequest$Type extends MessageType<ListDNSZonesRequest> {
    constructor() {
        super("teleport.lib.teleterm.vnet.v1.ListDNSZonesRequest", []);
    }
    create(value?: PartialMessage<ListDNSZonesRequest>): ListDNSZonesRequest {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<ListDNSZonesRequest>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: ListDNSZonesRequest): ListDNSZonesRequest {
        return target ?? this.create();
    }
    internalBinaryWrite(message: ListDNSZonesRequest, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.vnet.v1.ListDNSZonesRequest
 */
export const ListDNSZonesRequest = new ListDNSZonesRequest$Type();
// @generated message type with reflection information, may provide speed optimized methods
class ListDNSZonesResponse$Type extends MessageType<ListDNSZonesResponse> {
    constructor() {
        super("teleport.lib.teleterm.vnet.v1.ListDNSZonesResponse", [
            { no: 1, name: "dns_zones", kind: "scalar", repeat: 2 /*RepeatType.UNPACKED*/, T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<ListDNSZonesResponse>): ListDNSZonesResponse {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.dnsZones = [];
        if (value !== undefined)
            reflectionMergePartial<ListDNSZonesResponse>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: ListDNSZonesResponse): ListDNSZonesResponse {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* repeated string dns_zones */ 1:
                    message.dnsZones.push(reader.string());
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: ListDNSZonesResponse, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* repeated string dns_zones = 1; */
        for (let i = 0; i < message.dnsZones.length; i++)
            writer.tag(1, WireType.LengthDelimited).string(message.dnsZones[i]);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.vnet.v1.ListDNSZonesResponse
 */
export const ListDNSZonesResponse = new ListDNSZonesResponse$Type();
// @generated message type with reflection information, may provide speed optimized methods
class GetBackgroundItemStatusRequest$Type extends MessageType<GetBackgroundItemStatusRequest> {
    constructor() {
        super("teleport.lib.teleterm.vnet.v1.GetBackgroundItemStatusRequest", []);
    }
    create(value?: PartialMessage<GetBackgroundItemStatusRequest>): GetBackgroundItemStatusRequest {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<GetBackgroundItemStatusRequest>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: GetBackgroundItemStatusRequest): GetBackgroundItemStatusRequest {
        return target ?? this.create();
    }
    internalBinaryWrite(message: GetBackgroundItemStatusRequest, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.vnet.v1.GetBackgroundItemStatusRequest
 */
export const GetBackgroundItemStatusRequest = new GetBackgroundItemStatusRequest$Type();
// @generated message type with reflection information, may provide speed optimized methods
class GetBackgroundItemStatusResponse$Type extends MessageType<GetBackgroundItemStatusResponse> {
    constructor() {
        super("teleport.lib.teleterm.vnet.v1.GetBackgroundItemStatusResponse", [
            { no: 1, name: "status", kind: "enum", T: () => ["teleport.lib.teleterm.vnet.v1.BackgroundItemStatus", BackgroundItemStatus, "BACKGROUND_ITEM_STATUS_"] }
        ]);
    }
    create(value?: PartialMessage<GetBackgroundItemStatusResponse>): GetBackgroundItemStatusResponse {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.status = 0;
        if (value !== undefined)
            reflectionMergePartial<GetBackgroundItemStatusResponse>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: GetBackgroundItemStatusResponse): GetBackgroundItemStatusResponse {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* teleport.lib.teleterm.vnet.v1.BackgroundItemStatus status */ 1:
                    message.status = reader.int32();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: GetBackgroundItemStatusResponse, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* teleport.lib.teleterm.vnet.v1.BackgroundItemStatus status = 1; */
        if (message.status !== 0)
            writer.tag(1, WireType.Varint).int32(message.status);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.vnet.v1.GetBackgroundItemStatusResponse
 */
export const GetBackgroundItemStatusResponse = new GetBackgroundItemStatusResponse$Type();
/**
 * @generated ServiceType for protobuf service teleport.lib.teleterm.vnet.v1.VnetService
 */
export const VnetService = new ServiceType("teleport.lib.teleterm.vnet.v1.VnetService", [
    { name: "Start", options: {}, I: StartRequest, O: StartResponse },
    { name: "Stop", options: {}, I: StopRequest, O: StopResponse },
    { name: "ListDNSZones", options: {}, I: ListDNSZonesRequest, O: ListDNSZonesResponse },
    { name: "GetBackgroundItemStatus", options: {}, I: GetBackgroundItemStatusRequest, O: GetBackgroundItemStatusResponse }
]);