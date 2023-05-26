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

// CreateOSCConfigFile creates the osc config file (~/.oscrc) that contains
// API URL and credentials needed to authenticate with the API
func CreateOSCConfigFile(apiURL, username, password string) error {
	userHome, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("obtaining user's home directory: %w", err)
	}

	oscConfigFilePath := filepath.Join(userHome, ".oscrc")
	authFile := fmt.Sprintf(authFileFormat, apiURL, apiURL, username, password)

	if err := os.WriteFile(oscConfigFilePath, []byte(authFile), 0o600); err != nil {
		return fmt.Errorf("writing osc config file: %w", err)
	}

	return nil
}
