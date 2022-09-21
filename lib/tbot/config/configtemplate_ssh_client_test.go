/*
Copyright 2022 Gravitational, Inc.

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

package config

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/coreos/go-semver/semver"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/tbot/botfs"
	"github.com/gravitational/teleport/lib/tbot/identity"
	"github.com/gravitational/teleport/lib/utils/golden"
	"github.com/stretchr/testify/require"
)

func TestTemplateSSHClient_Render(t *testing.T) {
	tests := []struct {
		name       string
		sshVersion *semver.Version
		goldenName string
	}{
		{
			name:       "all enabled",
			sshVersion: semver.New("8.5.0"),
			goldenName: "ssh_config",
		},
		{
			name:       "no accepted algorithms",
			sshVersion: semver.New("8.0.0"),
			goldenName: "ssh_config_no_accepted_algos",
		},
		{
			name:       "no accepted and host keys algorithms",
			sshVersion: semver.New("7.3.0"),
			goldenName: "ssh_config_no_host_keys_algos",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			mockAuth := newMockAuth(t)

			cfg, err := NewDefaultConfig("example.com")
			require.NoError(t, err)

			mockBot := newMockBot(cfg, mockAuth)
			getSSHVersion := func() (*semver.Version, error) {
				return tt.sshVersion, nil
			}
			getExecutablePath := func() (string, error) {
				return "/path/to/tbot", nil
			}

			template := TemplateSSHClient{
				ProxyPort: 1337,
				generator: *config.NewCustomSSHConfigGenerator(getSSHVersion, getExecutablePath),
			}
			// ident is passed in, but not used.
			var ident *identity.Identity
			dest := &DestinationConfig{
				DestinationMixin: DestinationMixin{
					Directory: &DestinationDirectory{
						Path:     dir,
						Symlinks: botfs.SymlinksInsecure,
						ACLs:     botfs.ACLOff,
					},
				},
			}

			err = template.Render(context.Background(), mockBot, ident, dest)
			require.NoError(t, err)

			replaceTestDir := func(b []byte) []byte {
				return bytes.ReplaceAll(b, []byte(dir), []byte("/test/dir"))
			}

			knownHostBytes, err := os.ReadFile(filepath.Join(dir, knownHostsName))
			require.NoError(t, err)
			knownHostBytes = replaceTestDir(knownHostBytes)
			sshConfigBytes, err := os.ReadFile(filepath.Join(dir, sshConfigName))
			require.NoError(t, err)
			sshConfigBytes = replaceTestDir(sshConfigBytes)
			if golden.ShouldSet() {
				golden.SetNamed(t, "known_hosts", knownHostBytes)
				golden.SetNamed(t, "ssh_config", sshConfigBytes)
			}
			require.Equal(
				t, string(golden.GetNamed(t, "known_hosts")), string(knownHostBytes),
			)
			require.Equal(
				t, string(golden.GetNamed(t, tt.goldenName)), string(sshConfigBytes),
			)
		})
	}
}
