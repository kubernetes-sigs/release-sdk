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
}

// New returns a new Signer instance.
func New(options *Options) *Signer {
	if options.Logger == nil {
		options.Logger = logrus.New()
	}

	if options.Verbose {
		logs.Debug.SetOutput(os.Stderr)
		options.Logger.SetLevel(logrus.DebugLevel)
	}

	return &Signer{
		impl:    &defaultImpl{},
		options: options,
	}
}

// SetImpl can be used to set the internal implementation, which is mainly used
// for testing.
func (s *Signer) SetImpl(impl impl) {
	s.impl = impl
}

// log returns the internally set logger.
func (s *Signer) log() *logrus.Logger {
	return s.options.Logger
}

func (s *Signer) UploadBlob(path string) error {
	s.log().Infof("Uploading blob: %s", path)

	// TODO: unimplemented

	return nil
}

// SignImage can be used to sign any provided container image reference by
// using keyless signing.
func (s *Signer) SignImage(reference string) (*SignedObject, error) {
	s.log().Infof("Signing reference: %s", reference)

	// Ensure options to sign are correct
	if err := s.options.verifySignOptions(); err != nil {
		return nil, errors.Wrap(err, "checking signing options")
	}

	resetFn, err := s.enableExperimental()
	if err != nil {
		return nil, err
	}
	defer resetFn()

	ctx, cancel := s.options.context()
	defer cancel()

	// If we don't have a key path, we must ensure we can get an OIDC
	// token or there is no way to sign. Depending on the options set,
	// we may get the ID token from the cosign providers
	identityToken := ""
	if s.options.PrivateKeyPath == "" {
		tok, err := s.identityToken(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "getting identity token for keyless signing")
		}
		identityToken = tok
		if identityToken == "" {
			return nil, errors.New(
				"no private key or identity token are available, unable to sign",
			)
		}
	}

	ko := sign.KeyOpts{
		KeyRef:     s.options.PrivateKeyPath,
		IDToken:    identityToken,
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

	if err := s.impl.SignImageInternal(ctx, ko, regOpts,
		s.options.Annotations, images, "", s.options.AttachSignature, outputSignature,
		outputCertificate, "", true, false, "",
	); err != nil {
		return nil, errors.Wrapf(err, "sign reference: %s", reference)
	}

	if !s.options.AttachSignature {
		// TODO: https://github.com/kubernetes-sigs/release-sdk/issues/37
		return &SignedObject{}, nil
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
	s.log().Infof("Signing file path: %s", path)

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
	s.log().Infof("Verifying reference: %s", reference)

	resetFn, err := s.enableExperimental()
	if err != nil {
		return nil, err
	}
	defer resetFn()

	ctx, cancel := s.options.context()
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
	s.log().Infof("Verifying file path: %s", path)

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
			s.log().Errorf("Unable to reset cosign experimental mode: %v", err)
		}
	}, nil
}

// IsImageSigned takes an image reference and returns true if there are
// signatures available for it. It makes no signature verification, only
// checks to see if more than one signature is available.
func (s *Signer) IsImageSigned(imageRef string) (bool, error) {
	ref, err := s.impl.ParseReference(imageRef)
	if err != nil {
		return false, errors.Wrap(err, "parsing image reference")
	}

	simg, err := s.impl.SignedEntity(ref)
	if err != nil {
		return false, errors.Wrap(err, "getting signed entity from image reference")
	}

	sigs, err := s.impl.Signatures(simg)
	if err != nil {
		return false, errors.Wrap(err, "remote image")
	}

	signatures, err := s.impl.SignaturesList(sigs)
	if err != nil {
		return false, errors.Wrap(err, "fetching signatures")
	}

	return len(signatures) > 0, nil
}

// identityToken returns an identity token to perform keyless signing.
// If there is one set in the options we will use that one. If not,
// signer will try to get one from the cosign OIDC identity providers
// if options.EnableTokenProviders is set
func (s *Signer) identityToken(ctx context.Context) (string, error) {
	tok := s.options.IdentityToken
	if s.options.PrivateKeyPath == "" && s.options.IdentityToken == "" {
		// We only attempt to pull from the providers if the option is set
		if !s.options.EnableTokenProviders {
			s.log().Warn("No token set in options and OIDC providers are disabled")
			return "", nil
		}

		s.log().Info("No identity token was provided. Attempting to get one from supported providers.")
		token, err := s.impl.TokenFromProviders(ctx, s.log())
		if err != nil {
			return "", errors.Wrap(err, "getting identity token from providers")
		}
		tok = token
	}
	return tok, nil
}
