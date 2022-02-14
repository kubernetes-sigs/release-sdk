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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/pkg/cosign"
	"sigs.k8s.io/release-utils/env"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
//go:generate /usr/bin/env bash -c "cat ../scripts/boilerplate/boilerplate.generatego.txt signfakes/fake_impl.go > signfakes/_fake_impl.go && mv signfakes/_fake_impl.go signfakes/fake_impl.go"
type impl interface {
	VerifyFileInternal(*Signer, string) (*SignedObject, error)
	VerifyImageInternal(ctx context.Context, keyPath string, images []string) (*SignedObject, error)
	IsImageSignedInternal(context.Context, string) (bool, error)
	SignImageInternal(ctx context.Context, ko sign.KeyOpts, regOpts options.RegistryOptions,
		annotations map[string]interface{}, imgs []string, certPath string, upload bool,
		outputSignature string, outputCertificate string, payloadPath string, force bool,
		recursive bool, attachment string) error
	Setenv(string, string) error
	EnvDefault(string, string) string
}

func (*defaultImpl) VerifyFileInternal(signer *Signer, path string) (*SignedObject, error) {
	return signer.VerifyFile(path)
}

func (*defaultImpl) VerifyImageInternal(ctx context.Context, publickeyPath string, images []string) (*SignedObject, error) {
	v := verify.VerifyCommand{KeyRef: publickeyPath}
	return &SignedObject{}, v.Exec(ctx, images)
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

func (*defaultImpl) EnvDefault(key, def string) string {
	return env.Default(key, def)
}

// IsImageSignedInternal makes a call to the registry to check
// if there are signatures available for a given reference.
func (*defaultImpl) IsImageSignedInternal(
	ctx context.Context, imageRef string,
) (bool, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return false, errors.Wrap(err, "parsing image reference")
	}

	signatures, err := cosign.FetchSignaturesForReference(ctx, ref)
	if err != nil {
		return false, errors.Wrap(err, "fetching signarures")
	}

	return len(signatures) > 0, nil
}
