/*
Copyright 2026 The Kubernetes Authors.

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

package osc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOscConfigFilePath(t *testing.T) {
	t.Run("OSC_CONFIG takes precedence", func(t *testing.T) {
		t.Setenv("OSC_CONFIG", "/custom/path/oscrc")

		p, err := oscConfigFilePath()
		require.NoError(t, err)
		assert.Equal(t, "/custom/path/oscrc", p)
	})

	t.Run("legacy ~/.oscrc used if it exists", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("OSC_CONFIG", "")
		t.Setenv("XDG_CONFIG_HOME", "")

		legacyPath := filepath.Join(home, ".oscrc")
		require.NoError(t, os.WriteFile(legacyPath, []byte("[general]"), 0o600))

		p, err := oscConfigFilePath()
		require.NoError(t, err)
		assert.Equal(t, legacyPath, p)
	})

	t.Run("XDG_CONFIG_HOME used when set", func(t *testing.T) {
		home := t.TempDir()
		xdgConfig := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("OSC_CONFIG", "")
		t.Setenv("XDG_CONFIG_HOME", xdgConfig)

		p, err := oscConfigFilePath()
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(xdgConfig, "osc", "oscrc"), p)
	})

	t.Run("defaults to ~/.config/osc/oscrc", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("OSC_CONFIG", "")
		t.Setenv("XDG_CONFIG_HOME", "")

		p, err := oscConfigFilePath()
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(home, ".config", "osc", "oscrc"), p)
	})
}

func TestCreateOSCConfigFile(t *testing.T) {
	t.Run("creates config at XDG path with correct content", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("OSC_CONFIG", "")
		t.Setenv("XDG_CONFIG_HOME", "")

		err := CreateOSCConfigFile("https://api.opensuse.org", "testuser", "testpass")
		require.NoError(t, err)

		configPath := filepath.Join(home, ".config", "osc", "oscrc")
		content, err := os.ReadFile(configPath)
		require.NoError(t, err)

		assert.Contains(t, string(content), "apiurl = https://api.opensuse.org")
		assert.Contains(t, string(content), "user=testuser")
		assert.Contains(t, string(content), "pass=testpass")
		assert.Contains(t, string(content), "credentials_mgr_class=osc.credentials.PlaintextConfigFileCredentialsManager")

		info, err := os.Stat(configPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("creates config at legacy path when it exists", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("OSC_CONFIG", "")
		t.Setenv("XDG_CONFIG_HOME", "")

		legacyPath := filepath.Join(home, ".oscrc")
		require.NoError(t, os.WriteFile(legacyPath, []byte("old"), 0o600))

		err := CreateOSCConfigFile("https://api.opensuse.org", "testuser", "testpass")
		require.NoError(t, err)

		content, err := os.ReadFile(legacyPath)
		require.NoError(t, err)
		assert.Contains(t, string(content), "user=testuser")
	})
}
