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

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	cliOpts "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sirupsen/logrus"
)

// Signer is the main structure to be used by API consumers.
type Signer struct {
	impl
	options *Options
	log     *logrus.Logger
}

// New returns a new Signer instance.
func New(options *Options) *Signer {
	logger := logrus.New()

	if options.Verbose {
		logs.Debug.SetOutput(os.Stderr)
		logger.SetLevel(logrus.DebugLevel)
	}

	return &Signer{
		impl:    &defaultImpl{},
		options: options,
		log:     logger,
	}
}

// SetImpl can be used to set the internal implementation, which is mainly used
// for testing.
func (s *Signer) SetImpl(impl impl) {
	s.impl = impl
}

func (s *Signer) UploadBlob(path string) error {
	s.log.Infof("Uploading blob: %s", path)

	// TODO: unimplemented

	return nil
}

// SignImage can be used to sign any provided container image reference by
// using keyless signing.
func (s *Signer) SignImage(reference string) (*SignedObject, error) {
	s.log.Infof("Signing reference: %s", reference)

	os.Setenv("COSIGN_EXPERIMENTAL", "true")
	defer os.Setenv("COSIGN_EXPERIMENTAL", "")

	ko := sign.KeyOpts{
		KeyRef:     s.options.KeyPath,
		PassFunc:   generate.GetPass,
		FulcioURL:  cliOpts.DefaultFulcioURL,
		RekorURL:   cliOpts.DefaultRekorURL,
		OIDCIssuer: cliOpts.DefaultOIDCIssuerURL,

		InsecureSkipFulcioVerify: false,
	}

	regOpts := cliOpts.RegistryOptions{
		AllowInsecure: s.options.AllowInsecure,
	}

	imgs := []string{reference}

	outputSignature := ""
	if s.options.OutputSignaturePath == "" {
		outputSignature = s.options.OutputSignaturePath
	}

	outputCertificate := ""
	if s.options.OutputCertificatePath == "" {
		outputCertificate = s.options.OutputCertificatePath
	}

	err := s.SignImageInternal(context.Background(), ko, regOpts,
		s.options.Annotations, imgs, "", true, outputSignature,
		outputCertificate, "", true, false, "")
	if err != nil {
		return nil, errors.Wrapf(err, "verify reference: %s", reference)
	}

	object, err := s.VerifyInternal(s, reference)
	if err != nil {
		return nil, errors.Wrapf(err, "verify reference: %s", reference)
	}

	return object, nil
}

// SignFile can be used to sign any provided file path by using keyless
// signing.
func (s *Signer) SignFile(path string) (*SignedObject, error) {
	s.log.Infof("Signing file path: %s", path)

	// TODO: unimplemented

	object, err := s.VerifyInternal(s, path)
	if err != nil {
		return nil, errors.Wrapf(err, "verify file path: %s", path)
	}
	return object, nil
}

// Verify can be used to validate any remote reference. The returned signed
// object will contain additional information if the verification was
// successful.
func (s *Signer) Verify(reference string) (*SignedObject, error) {
	s.log.Infof("Verifying reference: %s", reference)

	// TODO: unimplemented

	return &SignedObject{}, nil
}
