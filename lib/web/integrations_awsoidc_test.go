/*
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

package web

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/uuid"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/web/ui"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

func TestBuildDeployServiceConfigureIAMScript(t *testing.T) {
	isBadParamErrFn := func(tt require.TestingT, err error, i ...any) {
		require.True(tt, trace.IsBadParameter(err), "expected bad parameter, got %v", err)
	}

	ctx := context.Background()
	env := newWebPack(t, 1)

	// Unauthenticated client for script downloading.
	publicClt := env.proxies[0].newClient(t)
	pathVars := []string{
		"webapi",
		"scripts",
		"integrations",
		"configure",
		"deployservice-iam.sh",
	}
	endpoint := publicClt.Endpoint(pathVars...)

	tests := []struct {
		name                 string
		reqRelativeURL       string
		reqQuery             url.Values
		errCheck             require.ErrorAssertionFunc
		expectedTeleportArgs string
	}{
		{
			name: "valid",
			reqQuery: url.Values{
				"awsRegion":       []string{"us-east-1"},
				"role":            []string{"myRole"},
				"taskRole":        []string{"taskRole"},
				"integrationName": []string{"myintegration"},
			},
			errCheck: require.NoError,
			expectedTeleportArgs: "integration configure deployservice-iam " +
				`--cluster=localhost ` +
				`--name=myintegration ` +
				`--aws-region=us-east-1 ` +
				`--role=myRole ` +
				`--task-role=taskRole`,
		},
		{
			name: "valid with symbols in role",
			reqQuery: url.Values{
				"awsRegion":       []string{"us-east-1"},
				"role":            []string{"Test+1=2,3.4@5-6_7"},
				"taskRole":        []string{"taskRole"},
				"integrationName": []string{"myintegration"},
			},
			errCheck: require.NoError,
			expectedTeleportArgs: "integration configure deployservice-iam " +
				`--cluster=localhost ` +
				`--name=myintegration ` +
				`--aws-region=us-east-1 ` +
				`--role=Test+1=2,3.4@5-6_7 ` +
				`--task-role=taskRole`,
		},
		{
			name: "missing aws-region",
			reqQuery: url.Values{
				"role":            []string{"myRole"},
				"taskRole":        []string{"taskRole"},
				"integrationName": []string{"myintegration"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing role",
			reqQuery: url.Values{
				"awsRegion":       []string{"us-east-1"},
				"taskRole":        []string{"taskRole"},
				"integrationName": []string{"myintegration"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing task role",
			reqQuery: url.Values{
				"awsRegion":       []string{"us-east-1"},
				"role":            []string{"role"},
				"integrationName": []string{"myintegration"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing integration name",
			reqQuery: url.Values{
				"awsRegion": []string{"us-east-1"},
				"role":      []string{"role"},
				"taskRole":  []string{"taskRole"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "trying to inject escape sequence into query params",
			reqQuery: url.Values{
				"awsRegion":       []string{"us-east-1"},
				"role":            []string{"role"},
				"taskRole":        []string{"taskRole"},
				"integrationName": []string{"'; rm -rf /tmp/dir; echo '"},
			},
			errCheck: isBadParamErrFn,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp, err := publicClt.Get(ctx, endpoint, tc.reqQuery)
			tc.errCheck(t, err)
			if err != nil {
				return
			}

			require.Contains(t, string(resp.Bytes()),
				fmt.Sprintf("teleportArgs='%s'\n", tc.expectedTeleportArgs),
			)
		})
	}
}

func TestBuildEICEConfigureIAMScript(t *testing.T) {
	isBadParamErrFn := func(tt require.TestingT, err error, i ...any) {
		require.True(tt, trace.IsBadParameter(err), "expected bad parameter, got %v", err)
	}

	ctx := context.Background()
	env := newWebPack(t, 1)

	// Unauthenticated client for script downloading.
	publicClt := env.proxies[0].newClient(t)
	pathVars := []string{
		"webapi",
		"scripts",
		"integrations",
		"configure",
		"eice-iam.sh",
	}
	endpoint := publicClt.Endpoint(pathVars...)

	tests := []struct {
		name                 string
		reqRelativeURL       string
		reqQuery             url.Values
		errCheck             require.ErrorAssertionFunc
		expectedTeleportArgs string
	}{
		{
			name: "valid",
			reqQuery: url.Values{
				"awsRegion": []string{"us-east-1"},
				"role":      []string{"myRole"},
			},
			errCheck: require.NoError,
			expectedTeleportArgs: "integration configure eice-iam " +
				"--aws-region=us-east-1 " +
				"--role=myRole",
		},
		{
			name: "valid with symbols in role",
			reqQuery: url.Values{
				"awsRegion": []string{"us-east-1"},
				"role":      []string{"Test+1=2,3.4@5-6_7"},
			},
			errCheck: require.NoError,
			expectedTeleportArgs: "integration configure eice-iam " +
				"--aws-region=us-east-1 " +
				"--role=Test+1=2,3.4@5-6_7",
		},
		{
			name: "missing aws-region",
			reqQuery: url.Values{
				"role": []string{"myRole"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing role",
			reqQuery: url.Values{
				"awsRegion": []string{"us-east-1"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "trying to inject escape sequence into query params",
			reqQuery: url.Values{
				"awsRegion": []string{"'; rm -rf /tmp/dir; echo '"},
				"role":      []string{"role"},
			},
			errCheck: isBadParamErrFn,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp, err := publicClt.Get(ctx, endpoint, tc.reqQuery)
			tc.errCheck(t, err)
			if err != nil {
				return
			}

			require.Contains(t, string(resp.Bytes()),
				fmt.Sprintf("teleportArgs='%s'\n", tc.expectedTeleportArgs),
			)
		})
	}
}

func TestBuildAWSOIDCIdPConfigureScript(t *testing.T) {
	isBadParamErrFn := func(tt require.TestingT, err error, i ...any) {
		require.True(tt, trace.IsBadParameter(err), "expected bad parameter, got %v", err)
	}

	ctx := context.Background()
	env := newWebPack(t, 1)

	// Unauthenticated client for script downloading.
	publicClt := env.proxies[0].newClient(t)
	pathVars := []string{
		"webapi",
		"scripts",
		"integrations",
		"configure",
		"awsoidc-idp.sh",
	}
	endpoint := publicClt.Endpoint(pathVars...)

	proxyPublicURL := env.proxies[0].webURL

	tests := []struct {
		name                 string
		reqRelativeURL       string
		reqQuery             url.Values
		errCheck             require.ErrorAssertionFunc
		expectedTeleportArgs string
	}{
		{
			name: "valid",
			reqQuery: url.Values{
				"awsRegion":       []string{"us-east-1"},
				"role":            []string{"myRole"},
				"integrationName": []string{"myintegration"},
			},
			errCheck: require.NoError,
			expectedTeleportArgs: "integration configure awsoidc-idp " +
				"--cluster=localhost " +
				"--name=myintegration " +
				"--role=myRole " +
				"--proxy-public-url=" + proxyPublicURL.String(),
		},
		{
			name: "valid with symbols in role",
			reqQuery: url.Values{
				"awsRegion":       []string{"us-east-1"},
				"role":            []string{"Test+1=2,3.4@5-6_7"},
				"integrationName": []string{"myintegration"},
			},
			errCheck: require.NoError,
			expectedTeleportArgs: "integration configure awsoidc-idp " +
				"--cluster=localhost " +
				"--name=myintegration " +
				"--role=Test+1=2,3.4@5-6_7 " +
				"--proxy-public-url=" + proxyPublicURL.String(),
		},
		{
			name: "missing role",
			reqQuery: url.Values{
				"integrationName": []string{"myintegration"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing integration name",
			reqQuery: url.Values{
				"role": []string{"role"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "trying to inject escape sequence into query params",
			reqQuery: url.Values{
				"awsRegion":       []string{"us-east-1"},
				"role":            []string{"role"},
				"integrationName": []string{"'; rm -rf /tmp/dir; echo '"},
			},
			errCheck: isBadParamErrFn,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp, err := publicClt.Get(ctx, endpoint, tc.reqQuery)
			tc.errCheck(t, err)
			if err != nil {
				return
			}

			require.Contains(t, string(resp.Bytes()),
				fmt.Sprintf("teleportArgs='%s'\n", tc.expectedTeleportArgs),
			)
		})
	}
}

func TestBuildListDatabasesConfigureIAMScript(t *testing.T) {
	isBadParamErrFn := func(tt require.TestingT, err error, i ...any) {
		require.True(tt, trace.IsBadParameter(err), "expected bad parameter, got %v", err)
	}

	ctx := context.Background()
	env := newWebPack(t, 1)

	// Unauthenticated client for script downloading.
	publicClt := env.proxies[0].newClient(t)
	pathVars := []string{
		"webapi",
		"scripts",
		"integrations",
		"configure",
		"listdatabases-iam.sh",
	}
	endpoint := publicClt.Endpoint(pathVars...)

	tests := []struct {
		name                 string
		reqRelativeURL       string
		reqQuery             url.Values
		errCheck             require.ErrorAssertionFunc
		expectedTeleportArgs string
	}{
		{
			name: "valid",
			reqQuery: url.Values{
				"awsRegion": []string{"us-east-1"},
				"role":      []string{"myRole"},
			},
			errCheck: require.NoError,
			expectedTeleportArgs: "integration configure listdatabases-iam " +
				"--aws-region=us-east-1 " +
				"--role=myRole",
		},
		{
			name: "valid with symbols in role",
			reqQuery: url.Values{
				"awsRegion": []string{"us-east-1"},
				"role":      []string{"Test+1=2,3.4@5-6_7"},
			},
			errCheck: require.NoError,
			expectedTeleportArgs: "integration configure listdatabases-iam " +
				"--aws-region=us-east-1 " +
				"--role=Test+1=2,3.4@5-6_7",
		},
		{
			name: "missing aws-region",
			reqQuery: url.Values{
				"role": []string{"myRole"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing role",
			reqQuery: url.Values{
				"awsRegion": []string{"us-east-1"},
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "trying to inject escape sequence into query params",
			reqQuery: url.Values{
				"awsRegion": []string{"'; rm -rf /tmp/dir; echo '"},
				"role":      []string{"role"},
			},
			errCheck: isBadParamErrFn,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := publicClt.Get(ctx, endpoint, tc.reqQuery)
			tc.errCheck(t, err)
			if err != nil {
				return
			}

			require.Contains(t, string(resp.Bytes()),
				fmt.Sprintf("teleportArgs='%s'\n", tc.expectedTeleportArgs),
			)
		})
	}
}

func TestAWSOIDCRequiredVPCSHelper(t *testing.T) {
	ctx := context.Background()
	env := newWebPack(t, 1)
	clt := env.proxies[0].client

	matchRegion := "us-east-1"
	matchAccountId := "123456789012"
	req := ui.AWSOIDCRequiredVPCSRequest{
		Region:    matchRegion,
		AccountID: matchAccountId,
	}

	upsertDbSvcFn := func(vpcId string, matcher []*types.DatabaseResourceMatcher) {
		if matcher == nil {
			matcher = []*types.DatabaseResourceMatcher{
				{
					Labels: &types.Labels{
						types.DiscoveryLabelAccountID: []string{matchAccountId},
						types.DiscoveryLabelRegion:    []string{matchRegion},
						types.DiscoveryLabelVPCID:     []string{vpcId},
					},
				},
			}
		}
		svc, err := types.NewDatabaseServiceV1(types.Metadata{
			Name:   uuid.NewString(),
			Labels: map[string]string{types.AWSOIDCAgentLabel: types.True},
		}, types.DatabaseServiceSpecV1{
			ResourceMatchers: matcher,
		})
		require.NoError(t, err)
		_, err = env.server.Auth().UpsertDatabaseService(ctx, svc)
		require.NoError(t, err)
	}

	extractKeysFn := func(resp *ui.AWSOIDCRequiredVPCSResponse) []string {
		keys := make([]string, 0, len(resp.VPCMapOfSubnets))
		for k := range resp.VPCMapOfSubnets {
			keys = append(keys, k)
		}
		return keys
	}

	vpcs := []string{"vpc-1", "vpc-2", "vpc-3", "vpc-4", "vpc-5"}
	rdss := []rdsTypes.DBInstance{}
	for _, vpc := range vpcs {
		rdss = append(rdss, rdsTypes.DBInstance{
			DBInstanceStatus:     stringPointer("available"),
			DBInstanceIdentifier: stringPointer(fmt.Sprintf("db-%v", vpc)),
			DbiResourceId:        stringPointer("db-123"),
			Engine:               stringPointer("postgres"),
			DBInstanceArn:        stringPointer("arn:aws:iam::123456789012:role/MyARN"),

			Endpoint: &rdsTypes.Endpoint{
				Address: stringPointer("endpoint.amazonaws.com"),
				Port:    aws.Int32(5432),
			},
			DBSubnetGroup: &rdsTypes.DBSubnetGroup{
				Subnets: []rdsTypes.Subnet{{SubnetIdentifier: aws.String(fmt.Sprintf("subnet-for-%s", vpc))}},
				VpcId:   aws.String(vpc),
			},
		})
	}

	mockListClient := mockListDatabasesClient{dbInstances: rdss}

	// Double check we start with 0 db svcs.
	s, err := env.server.Auth().ListResources(ctx, proto.ListResourcesRequest{
		ResourceType: types.KindDatabaseService,
	})
	require.NoError(t, err)
	require.Len(t, s.Resources, 0)

	// All vpc's required.
	resp, err := awsOIDCRequiredVPCSHelper(ctx, req, mockListClient, clt)
	require.NoError(t, err)
	require.Len(t, resp.VPCMapOfSubnets, 5)
	require.ElementsMatch(t, vpcs, extractKeysFn(resp))

	// Insert two valid database services.
	upsertDbSvcFn("vpc-1", []*types.DatabaseResourceMatcher{
		{
			Labels: &types.Labels{
				types.DiscoveryLabelAccountID: []string{matchAccountId},
			},
		},
		{
			Labels: &types.Labels{
				types.DiscoveryLabelVPCID:  []string{"vpc-1"},
				types.DiscoveryLabelRegion: []string{matchRegion},
			},
		},
	})
	upsertDbSvcFn("vpc-5", []*types.DatabaseResourceMatcher{
		{
			Labels: &types.Labels{
				types.DiscoveryLabelAccountID: []string{matchAccountId},
			},
		},
		{
			Labels: &types.Labels{
				types.DiscoveryLabelRegion: []string{matchRegion},
			},
		},
		{
			Labels: &types.Labels{
				types.DiscoveryLabelVPCID:  []string{"vpc-5"},
				types.DiscoveryLabelRegion: []string{matchRegion},
			},
		},
	})

	// Insert two invalid database services.
	upsertDbSvcFn("vpc-2", []*types.DatabaseResourceMatcher{
		{
			Labels: &types.Labels{
				types.DiscoveryLabelAccountID: []string{matchAccountId},
				types.DiscoveryLabelRegion:    []string{"us-east-2"}, // not matching region
				types.DiscoveryLabelVPCID:     []string{"vpc-2"},
			},
		},
	})
	upsertDbSvcFn("vpc-2a", []*types.DatabaseResourceMatcher{
		{
			Labels: &types.Labels{
				types.DiscoveryLabelAccountID: []string{matchAccountId},
				types.DiscoveryLabelRegion:    []string{matchRegion},
				types.DiscoveryLabelVPCID:     []string{"vpc-2"},
			},
		},
		{
			Labels: &types.Labels{
				"something": []string{"extra"}, // not matching b/c extra label
			},
		},
	})

	// Double check services were created.
	s, err = env.server.Auth().ListResources(ctx, proto.ListResourcesRequest{
		ResourceType: types.KindDatabaseService,
	})
	require.NoError(t, err)
	require.Len(t, s.Resources, 4)

	// Test that only 3 vpcs are required.
	resp, err = awsOIDCRequiredVPCSHelper(ctx, req, mockListClient, clt)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"vpc-2", "vpc-3", "vpc-4"}, extractKeysFn(resp))

	// Insert the rest of db services
	upsertDbSvcFn("vpc-2", nil)
	upsertDbSvcFn("vpc-3", nil)
	upsertDbSvcFn("vpc-4", nil)

	// Test no required vpcs.
	resp, err = awsOIDCRequiredVPCSHelper(ctx, req, mockListClient, clt)
	require.NoError(t, err)
	require.Empty(t, resp.VPCMapOfSubnets)
}

func stringPointer(s string) *string {
	return &s
}

type mockListDatabasesClient struct {
	dbInstances []rdsTypes.DBInstance
}

func (m mockListDatabasesClient) DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{
		DBInstances: m.dbInstances,
	}, nil
}

func (m mockListDatabasesClient) DescribeDBClusters(ctx context.Context, params *rds.DescribeDBClustersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	return &rds.DescribeDBClustersOutput{}, nil
}
