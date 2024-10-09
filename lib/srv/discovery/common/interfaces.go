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

package common

import (
	"context"

	"github.com/gravitational/teleport/api/types"
)

// Fetcher defines the common methods across all fetchers.
type Fetcher interface {
	// Get returns the list of resources from the cloud after applying the filters.
	Get(ctx context.Context) (types.ResourcesWithLabels, error)
	// ResourceType identifies the resource type the fetcher is returning.
	ResourceType() string
	// FetcherType identifies the Fetcher Type (cloud resource name).
	// Eg, ec2, rds, aks, gce
	FetcherType() string
	// Cloud returns the cloud the fetcher is operating.
	Cloud() string
}

type TAGSync interface {
	// Poll polls all AWS resources and returns the result.
	Poll(context.Context, Features) (*Resources, error)
	// Status reports the last known status of the fetcher.
	Status() (uint64, error)
	// DiscoveryConfigName returns the name of the Discovery Config.
	DiscoveryConfigName() string
	// IsFromDiscoveryConfig returns true if the fetcher is associated with a Discovery Config.
	IsFromDiscoveryConfig() bool
	// GetAccountID returns the AWS account ID.
	GetAccountID() string
}
