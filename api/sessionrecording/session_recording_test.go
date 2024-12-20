/*
Copyright 2024 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sessionrecording_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/sessionrecording"
)

// TestReadCorruptedRecording tests that the streamer can successfully decode the kind of corrupted
// recordings that some older bugged versions of teleport might end up producing when under heavy load/throttling.
func TestReadCorruptedRecording(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f, err := os.Open("testdata/corrupted-session")
	require.NoError(t, err)
	defer f.Close()

	reader := sessionrecording.NewReader(f)
	defer reader.Close()

	events, err := reader.ReadAll(ctx)
	require.NoError(t, err)

	// verify that the expected number of events are extracted
	require.Len(t, events, 12)
}
