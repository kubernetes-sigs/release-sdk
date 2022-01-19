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
	"os"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/pkg/errors"
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

// Sign can be used to sign any provided reference by using keyless signing.
func (s *Signer) Sign(reference string) (*SignedObject, error) {
	s.log.Infof("Signing reference: %s", reference)

	// TODO: unimplemented

	object, err := s.VerifyInternal(s, reference)
	if err != nil {
		return nil, errors.Wrapf(err, "verify reference: %s", reference)
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
