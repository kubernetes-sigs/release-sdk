/*
Copyright 2023 The Kubernetes Authors.

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
	"fmt"
	"os"
	"path/filepath"
)

const (
	authFileFormat = `
[general]
apiurl = %s

[%s]
user=%s
pass=%s
credentials_mgr_class=osc.credentials.PlaintextConfigFileCredentialsManager
`
)

// oscConfigFilePath returns the path to the osc config file.
// It follows the same lookup order as osc itself:
// 1. $OSC_CONFIG if set
// 2. ~/.oscrc if it exists (legacy path)
// 3. $XDG_CONFIG_HOME/osc/oscrc (default for osc >= 1.0).
func oscConfigFilePath() (string, error) {
	if p := os.Getenv("OSC_CONFIG"); p != "" {
		return p, nil
	}

	userHome, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("obtaining user's home directory: %w", err)
	}

	legacy := filepath.Join(userHome, ".oscrc")
	if _, err := os.Stat(legacy); err == nil {
		return legacy, nil
	}

	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(userHome, ".config")
	}

	return filepath.Join(configHome, "osc", "oscrc"), nil
}

// CreateOSCConfigFile creates the osc config file that contains
// API URL and credentials needed to authenticate with the API.
func CreateOSCConfigFile(apiURL, username, password string) error {
	configPath, err := oscConfigFilePath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("creating osc config directory: %w", err)
	}

	authFile := fmt.Sprintf(authFileFormat, apiURL, apiURL, username, password)

	if err := os.WriteFile(configPath, []byte(authFile), 0o600); err != nil {
		return fmt.Errorf("writing osc config file: %w", err)
	}

	return nil
}
