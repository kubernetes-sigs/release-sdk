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
	"context"
	"os"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
//go:generate /usr/bin/env bash -c "cat ../scripts/boilerplate/boilerplate.generatego.txt signfakes/fake_impl.go > signfakes/_fake_impl.go && mv signfakes/_fake_impl.go signfakes/fake_impl.go"
type impl interface {
	VerifyFileInternal(*Signer, string) (*SignedObject, error)
	VerifyImageInternal(*Signer, string) (*SignedObject, error)
	SignImageInternal(ctx context.Context, ko sign.KeyOpts, regOpts options.RegistryOptions,
		annotations map[string]interface{}, imgs []string, certPath string, upload bool,
		outputSignature string, outputCertificate string, payloadPath string, force bool,
		recursive bool, attachment string) error
	Setenv(string, string) error
}

func (*defaultImpl) VerifyFileInternal(signer *Signer, path string) (*SignedObject, error) {
	return signer.VerifyFile(path)
}

func (*defaultImpl) VerifyImageInternal(signer *Signer, reference string) (*SignedObject, error) {
	return signer.VerifyImage(reference)
}

func (*defaultImpl) SignImageInternal(ctx context.Context, ko sign.KeyOpts, regOpts options.RegistryOptions, // nolint: gocritic
	annotations map[string]interface{}, imgs []string, certPath string, upload bool,
	outputSignature string, outputCertificate string, payloadPath string, force bool,
	recursive bool, attachment string) error {
	return sign.SignCmd(
		ctx, ko, regOpts, annotations, imgs, certPath, upload, outputSignature,
		outputCertificate, payloadPath, force, recursive, attachment,
	)
}

func (*defaultImpl) Setenv(key, value string) error {
	return os.Setenv(key, value)
}
