/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/header/v1/metadata.proto" (package "teleport.header.v1", syntax proto3)
// tslint:disable
// @ts-nocheck
//
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
//
import type { BinaryWriteOptions } from "@protobuf-ts/runtime";
import type { IBinaryWriter } from "@protobuf-ts/runtime";
import { WireType } from "@protobuf-ts/runtime";
import type { BinaryReadOptions } from "@protobuf-ts/runtime";
import type { IBinaryReader } from "@protobuf-ts/runtime";
import { UnknownFieldHandler } from "@protobuf-ts/runtime";
import type { PartialMessage } from "@protobuf-ts/runtime";
import { reflectionMergePartial } from "@protobuf-ts/runtime";
import { MessageType } from "@protobuf-ts/runtime";
import { Timestamp } from "../../../google/protobuf/timestamp_pb";
/**
 * Metadata is resource metadata.
 *
 * @generated from protobuf message teleport.header.v1.Metadata
 */
export interface Metadata {
    /**
     * name is an object name.
     *
     * @generated from protobuf field: string name = 1;
     */
    name: string;
    /**
     * namespace is object namespace. The field should be called "namespace"
     * when it returns in Teleport 2.4.
     *
     * @generated from protobuf field: string namespace = 2;
     */
    namespace: string;
    /**
     * description is object description.
     *
     * @generated from protobuf field: string description = 3;
     */
    description: string;
    /**
     * labels is a set of labels.
     *
     * @generated from protobuf field: map<string, string> labels = 5;
     */
    labels: {
        [key: string]: string;
    };
    /**
     * expires is a global expiry time header can be set on any resource in the
     * system.
     *
     * @generated from protobuf field: google.protobuf.Timestamp expires = 6;
     */
    expires?: Timestamp;
    /**
     * revision is an opaque identifier which tracks the versions of a resource
     * over time. Clients should ignore and not alter its value but must return
     * the revision in any updates of a resource.
     *
     * @generated from protobuf field: string revision = 8;
     */
    revision: string;
}
// @generated message type with reflection information, may provide speed optimized methods
class Metadata$Type extends MessageType<Metadata> {
    constructor() {
        super("teleport.header.v1.Metadata", [
            { no: 1, name: "name", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "namespace", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 3, name: "description", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 5, name: "labels", kind: "map", K: 9 /*ScalarType.STRING*/, V: { kind: "scalar", T: 9 /*ScalarType.STRING*/ } },
            { no: 6, name: "expires", kind: "message", T: () => Timestamp },
            { no: 8, name: "revision", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<Metadata>): Metadata {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.name = "";
        message.namespace = "";
        message.description = "";
        message.labels = {};
        message.revision = "";
        if (value !== undefined)
            reflectionMergePartial<Metadata>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: Metadata): Metadata {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string name */ 1:
                    message.name = reader.string();
                    break;
                case /* string namespace */ 2:
                    message.namespace = reader.string();
                    break;
                case /* string description */ 3:
                    message.description = reader.string();
                    break;
                case /* map<string, string> labels */ 5:
                    this.binaryReadMap5(message.labels, reader, options);
                    break;
                case /* google.protobuf.Timestamp expires */ 6:
                    message.expires = Timestamp.internalBinaryRead(reader, reader.uint32(), options, message.expires);
                    break;
                case /* string revision */ 8:
                    message.revision = reader.string();
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
    private binaryReadMap5(map: Metadata["labels"], reader: IBinaryReader, options: BinaryReadOptions): void {
        let len = reader.uint32(), end = reader.pos + len, key: keyof Metadata["labels"] | undefined, val: Metadata["labels"][any] | undefined;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case 1:
                    key = reader.string();
                    break;
                case 2:
                    val = reader.string();
                    break;
                default: throw new globalThis.Error("unknown map entry field for field teleport.header.v1.Metadata.labels");
            }
        }
        map[key ?? ""] = val ?? "";
    }
    internalBinaryWrite(message: Metadata, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string name = 1; */
        if (message.name !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.name);
        /* string namespace = 2; */
        if (message.namespace !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.namespace);
        /* string description = 3; */
        if (message.description !== "")
            writer.tag(3, WireType.LengthDelimited).string(message.description);
        /* map<string, string> labels = 5; */
        for (let k of globalThis.Object.keys(message.labels))
            writer.tag(5, WireType.LengthDelimited).fork().tag(1, WireType.LengthDelimited).string(k).tag(2, WireType.LengthDelimited).string(message.labels[k]).join();
        /* google.protobuf.Timestamp expires = 6; */
        if (message.expires)
            Timestamp.internalBinaryWrite(message.expires, writer.tag(6, WireType.LengthDelimited).fork(), options).join();
        /* string revision = 8; */
        if (message.revision !== "")
            writer.tag(8, WireType.LengthDelimited).string(message.revision);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.header.v1.Metadata
 */
export const Metadata = new Metadata$Type();
