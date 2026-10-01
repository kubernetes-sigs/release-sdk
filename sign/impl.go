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
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/cosign/v3/pkg/providers"
	_ "github.com/sigstore/cosign/v3/pkg/providers/buildkite"  // register provider
	_ "github.com/sigstore/cosign/v3/pkg/providers/envvar"     // register provider
	_ "github.com/sigstore/cosign/v3/pkg/providers/filesystem" // register provider
	_ "github.com/sigstore/cosign/v3/pkg/providers/github"     // register provider
	_ "github.com/sigstore/cosign/v3/pkg/providers/google"     // register provider
	_ "github.com/sigstore/cosign/v3/pkg/providers/spiffe"     // register provider
	rekorgenerated "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"sigs.k8s.io/release-utils/helpers"
)

type defaultImpl struct {
	mu             sync.Mutex
	tufGroup       singleflight.Group
	tufClient      *tuf.Client
	tufFetched     time.Time
	trustedRoot    *root.TrustedRoot
	signingConf    *root.SigningConfig
	rekorClientURL string
	rekor          *rekorgenerated.Rekor
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
//go:generate /usr/bin/env bash -c "cat ../scripts/boilerplate/boilerplate.generatego.txt signfakes/fake_impl.go > signfakes/_fake_impl.go && mv signfakes/_fake_impl.go signfakes/fake_impl.go"
type impl interface {
	VerifyFileInternal(ctx context.Context, opts *Options, fileSHA256 string, useTlog bool) error
	VerifyImageInternal(ctx context.Context, opts *Options, reference string) (digest string, err error)
	SignImageInternal(ctx context.Context, opts *Options, identityToken, reference string) error
	SignFileInternal(ctx context.Context, opts *Options, identityToken, path string) error
	TlogEntryUUIDs(ctx context.Context, opts *Options, sha256 string) ([]string, error)
	TokenFromProviders(context.Context, *logrus.Logger) (string, error)
	FileExists(string) bool
	ParseReference(string, ...name.Option) (name.Reference, error)
	Digest(ref string, opt ...crane.Option) (string, error)
	NewWithContext(context.Context, name.Registry, authn.Authenticator, http.RoundTripper, []string) (http.RoundTripper, error)
	ImagesSigned(context.Context, *Signer, ...string) (*sync.Map, error)
}

func (d *defaultImpl) VerifyFileInternal(ctx context.Context, opts *Options, fileSHA256 string, useTlog bool) error {
	return d.verifyFile(ctx, opts, fileSHA256, useTlog)
}

func (d *defaultImpl) VerifyImageInternal(ctx context.Context, opts *Options, reference string) (string, error) {
	return d.verifyImage(ctx, opts, reference)
}

func (d *defaultImpl) SignImageInternal(ctx context.Context, opts *Options, identityToken, reference string) error {
	return d.signImage(ctx, opts, identityToken, reference)
}

func (d *defaultImpl) SignFileInternal(ctx context.Context, opts *Options, identityToken, path string) error {
	return d.signFile(ctx, opts, identityToken, path)
}

func (d *defaultImpl) TlogEntryUUIDs(ctx context.Context, opts *Options, sha256 string) ([]string, error) {
	return d.tlogEntryUUIDs(ctx, opts, sha256)
}

// TokenFromProviders will try the cosign OIDC providers to get an
// oidc token from them.
func (d *defaultImpl) TokenFromProviders(ctx context.Context, logger *logrus.Logger) (string, error) {
	if !d.IdentityProvidersEnabled(ctx) {
		logger.Warn("No OIDC provider enabled. Token cannot be obtained automatically.")

		return "", nil
	}

	tok, err := providers.Provide(ctx, "sigstore")
	if err != nil {
		return "", fmt.Errorf("fetching oidc token from environment: %w", err)
	}

	return tok, nil
}

// FileExists returns true if a file exists.
func (*defaultImpl) FileExists(path string) bool {
	return helpers.Exists(path)
}

// IdentityProvidersEnabled returns true if any of the cosign
// identity providers is able to obteain an OIDC identity token
// suitable for keyless signing,.
func (*defaultImpl) IdentityProvidersEnabled(ctx context.Context) bool {
	return providers.Enabled(ctx)
}

func (*defaultImpl) ParseReference(
	s string, opts ...name.Option,
) (name.Reference, error) {
	return name.ParseReference(s, opts...)
}

func (*defaultImpl) Digest(
	ref string, opts ...crane.Option,
) (string, error) {
	return crane.Digest(ref, opts...)
}

func (*defaultImpl) NewWithContext(
	ctx context.Context,
	reg name.Registry,
	auth authn.Authenticator,
	t http.RoundTripper,
	scopes []string,
) (http.RoundTripper, error) {
	return transport.NewWithContext(ctx, reg, auth, t, scopes)
}

func (d *defaultImpl) ImagesSigned(ctx context.Context, s *Signer, refs ...string) (*sync.Map, error) {
	return s.ImagesSigned(ctx, refs...)
}
