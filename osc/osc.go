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

	"sigs.k8s.io/release-utils/command"
)

const (
	// OSCExecutable is the name of the OpenBuildService CLI executable
	OSCExecutable = "osc"
)

// PreCheck checks if all requirements are fulfilled to run this package and
// all sub-packages
func PreCheck() error {
	for _, e := range []string{
		OSCExecutable,
	} {
		if !command.Available(e) {
			return fmt.Errorf(
				"%s executable is not available in $PATH", e,
			)
		}
	}

	return nil
}

// OSC can be used to run a 'osc' command
func OSC(args ...string) error {
	return command.New(OSCExecutable, args...).RunSilentSuccess()
}

// OSCOutput can be used to run a 'osc' command while capturing its output
func OSCOutput(args ...string) (string, error) {
	stream, err := command.New(OSCExecutable, args...).RunSilentSuccessOutput()
	if err != nil {
		return "", fmt.Errorf("executing %s: %w", OSCExecutable, err)
	}
	return stream.OutputTrimNL(), nil
}

// GSUtilStatus can be used to run a 'osc' command while capturing its status
func OSCStatus(args ...string) (*command.Status, error) {
	return command.New(OSCExecutable, args...).Run()
}
