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
	cliOpts "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sirupsen/logrus"
)

// Signer is the main structure to be used by API consumers.
type Signer struct {
	impl    impl
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

	resetFn, err := s.enableExperimental()
	if err != nil {
		return nil, err
	}
	defer resetFn()

	ko := sign.KeyOpts{
		KeyRef:     s.options.PrivateKeyPath,
		PassFunc:   s.options.PassFunc,
		FulcioURL:  cliOpts.DefaultFulcioURL,
		RekorURL:   cliOpts.DefaultRekorURL,
		OIDCIssuer: cliOpts.DefaultOIDCIssuerURL,

		InsecureSkipFulcioVerify: false,
	}

	regOpts := cliOpts.RegistryOptions{
		AllowInsecure: s.options.AllowInsecure,
	}

	images := []string{reference}

	outputSignature := ""
	if s.options.OutputSignaturePath == "" {
		outputSignature = s.options.OutputSignaturePath
	}

	outputCertificate := ""
	if s.options.OutputCertificatePath == "" {
		outputCertificate = s.options.OutputCertificatePath
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.options.Timeout)
	defer cancel()

	if err := s.impl.SignImageInternal(ctx, ko, regOpts,
		s.options.Annotations, images, "", true, outputSignature,
		outputCertificate, "", true, false, "",
	); err != nil {
		return nil, errors.Wrapf(err, "sign reference: %s", reference)
	}

	object, err := s.impl.VerifyImageInternal(ctx, s.options.PublicKeyPath, images)
	if err != nil {
		return nil, errors.Wrapf(err, "verify reference: %s", images)
	}

	return object, nil
}

// SignFile can be used to sign any provided file path by using keyless
// signing.
func (s *Signer) SignFile(path string) (*SignedObject, error) {
	s.log.Infof("Signing file path: %s", path)

	// TODO: unimplemented

	object, err := s.impl.VerifyFileInternal(s, path)
	if err != nil {
		return nil, errors.Wrapf(err, "verify file path: %s", path)
	}
	return object, nil
}

// VerifyImage can be used to validate any provided container image reference by
// using keyless signing.
func (s *Signer) VerifyImage(reference string) (*SignedObject, error) {
	s.log.Infof("Verifying reference: %s", reference)

	resetFn, err := s.enableExperimental()
	if err != nil {
		return nil, err
	}
	defer resetFn()

	ctx, cancel := context.WithTimeout(context.Background(), s.options.Timeout)
	defer cancel()
	images := []string{reference}
	object, err := s.impl.VerifyImageInternal(ctx, s.options.PublicKeyPath, images)
	if err != nil {
		return nil, errors.Wrapf(err, "verify image reference: %s", images)
	}
	return object, nil
}

// VerifyFile can be used to validate any provided file path.
func (s *Signer) VerifyFile(path string) (*SignedObject, error) {
	s.log.Infof("Verifying file path: %s", path)

	// TODO: unimplemented

	return &SignedObject{}, nil
}

// enableExperimental sets the cosign experimental mode to true. It also
// returns a resetFn to recover the original state within the environment.
func (s *Signer) enableExperimental() (resetFn func(), err error) {
	const key = "COSIGN_EXPERIMENTAL"
	previousValue := s.impl.EnvDefault(key, "")
	if err := s.impl.Setenv(key, "true"); err != nil {
		return nil, errors.Wrap(err, "enable cosign experimental mode")
	}
	return func() {
		if err := s.impl.Setenv(key, previousValue); err != nil {
			s.log.Errorf("Unable to reset cosign experimental mode: %v", err)
		}
	}, nil
}

// IsImageSigned takes an image reference and returns true if there are
// signatures available for it. It makes no signature verification, only
// checks to see if more than one signature is available.
func (s *Signer) IsImageSigned(imageRef string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.options.Timeout)
	defer cancel()

	return s.impl.IsImageSignedInternal(ctx, imageRef)
}
