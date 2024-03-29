/*
Copyright 2020 The Kubernetes Authors.

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

package object

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//go:generate /usr/bin/env bash -c "cat ../scripts/boilerplate/boilerplate.generatego.txt objectfakes/fake_store.go > objectfakes/_fake_store.go && mv objectfakes/_fake_store.go objectfakes/fake_store.go"

// Store is an interface modeling supported filestore operations
//
// Store is an interface modeling supported filestore operations
//
//counterfeiter:generate . Store
type Store interface {
	// Configure options
	SetOptions(opts ...OptFn)

	// Path operations
	NormalizePath(pathParts ...string) (string, error)
	IsPathNormalized(path string) bool
	PathExists(path string) (bool, error)

	// Copy operations
	// TODO: Determine if these methods should even be part of the interface
	// TODO: Maybe overly specific. Consider reducing these down to Copy()
	CopyToRemote(local, remote string) error
	CopyToLocal(remote, local string) error
	CopyBucketToBucket(src, dst string) error
	RsyncRecursive(src, dst string) error

	// TODO: Overly specific. We should only care these methods during a release.
	GetReleasePath(bucket, gcsRoot, version string, fast bool) (string, error)
	GetMarkerPath(bucket, gcsRoot string, fast bool) (string, error)
}

type OptFn func(Store)
