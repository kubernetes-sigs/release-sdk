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

	"github.com/blang/semver/v4"

	"sigs.k8s.io/release-utils/command"
)

const (
	// OSCExecutable is the name of the OpenBuildService CLI executable.
	OSCExecutable = "osc"
)

// PreCheck checks if all requirements are fulfilled to run this package and
// all sub-packages.
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

// OSC can be used to run a 'osc' command.
func OSC(workDir string, args ...string) error {
	return command.NewWithWorkDir(workDir, OSCExecutable, args...).RunSilentSuccess()
}

// Output can be used to run a 'osc' command while capturing its output.
func Output(workDir string, args ...string) (string, error) {
	stream, err := command.NewWithWorkDir(workDir, OSCExecutable, args...).RunSilentSuccessOutput()
	if err != nil {
		return "", fmt.Errorf("executing %s: %w", OSCExecutable, err)
	}

	return stream.OutputTrimNL(), nil
}

// Status can be used to run a 'osc' command while capturing its status.
func Status(workDir string, args ...string) (*command.Status, error) {
	return command.NewWithWorkDir(workDir, OSCExecutable, args...).Run()
}

// WaitResults waits for the build results. If can fail on error if an osc
// version >= 1.8.0 is being used.
func WaitResults(project, packageName string) error {
	ver, err := Version()
	if err != nil {
		return fmt.Errorf("retrieve version: %w", err)
	}

	args := []string{
		"results",
		"-w",
		fmt.Sprintf("%s/%s", project, packageName),
	}

	// Version 1.8.0 contains the feature to fail on wait error
	// ref: https://github.com/openSUSE/osc/pull/1573
	if ver.GE(semver.Version{Major: 1, Minor: 8}) {
		args = append(args, "-F")
	}

	return command.New(OSCExecutable, args...).RunSuccess()
}

// Version returns the semver version of the osc executable.
func Version() (*semver.Version, error) {
	out, err := command.New(OSCExecutable, "version").RunSilentSuccessOutput()
	if err != nil {
		return nil, fmt.Errorf("run version command: %w", err)
	}

	ver, err := semver.Parse(out.OutputTrimNL())
	if err != nil {
		return nil, fmt.Errorf("parse semver version: %w", err)
	}

	return &ver, nil
}
