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

package mocks

import (
	"context"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/gravitational/trace"
)

// STSClient fakes AWS SDK v2 STSClient API.
// It also wraps the v1 STSClient mock client, so callers can use it in tests for both
// the v1 and v2 interfaces.
// This is useful when recording assumed roles and some services use v1
// while others use a v2 STSClient client.
// For example:
//
// f := &STSClient{}
// a.stsClientV1 = &f.STSClientV1
// b.stsClientV2 = f
// ...
// gotRoles := f.GetAssumedRoleARNs() // returns roles that were assumed with either v1 or v2 client.
type STSClient struct {
	STSClientV1

	root               *STSClient
	credentialProvider aws.CredentialsProvider
}

func (m *STSClient) AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	// Every fake client will retrieve its credentials if it has them, and then
	// delegate the AssumeRole call to the root faked client.
	// In this way, each role in a chain of roles will be assumed and recorded
	// by the root fake STS client.
	if m.credentialProvider != nil {
		_, err := m.credentialProvider.Retrieve(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	if m.root != nil {
		return m.root.AssumeRole(ctx, in, optFns...)
	}

	m.STSClientV1.mu.Lock()
	defer m.STSClientV1.mu.Unlock()
	if !slices.Contains(m.assumedRoleARNs, aws.ToString(in.RoleArn)) {
		m.assumedRoleARNs = append(m.assumedRoleARNs, aws.ToString(in.RoleArn))
		m.assumedRoleExternalIDs = append(m.assumedRoleExternalIDs, aws.ToString(in.ExternalId))
	}
	expiry := time.Now().Add(60 * time.Minute)
	return &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     in.RoleArn,
			SecretAccessKey: aws.String("secret"),
			SessionToken:    aws.String("token"),
			Expiration:      &expiry,
		},
	}, nil
}
