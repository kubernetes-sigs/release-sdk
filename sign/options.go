/*
Copyright 2022 The Kubernetes Authors.

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

package sign

import (
	"time"

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/pkg/cosign"
)

// Options can be used to modify the behavior of the signer.
type Options struct {
	// Verbose can be used to enable a higher log verbosity
	Verbose bool

	// Timeout is the default timeout for network operations.
	// Defaults to 3 minutes
	Timeout time.Duration

	AllowInsecure         bool
	OutputSignaturePath   string
	OutputCertificatePath string
	Annotations           map[string]interface{}
	KeyPath               string

	// PassFunc is a function that returns a slice of bytes that will be used
	// as a password for decrypting the cosign key.
	// Defaults to a function that reads from stdin and asks for confirmation
	PassFunc cosign.PassFunc
}

// Default returns a default Options instance.
func Default() *Options {
	return &Options{
		Timeout:  3 * time.Minute,
		PassFunc: generate.GetPass,
	}
}
