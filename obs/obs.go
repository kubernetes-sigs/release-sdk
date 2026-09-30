/*
Copyright 2026 The Kubernetes Authors.

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

package obs

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultAPIURL is the API endpoint of the reference OBS instance.
	DefaultAPIURL = "https://api.opensuse.org"

	// DefaultTimeout is the timeout used by the default HTTP client.
	DefaultTimeout = 60 * time.Second

	// contentTypeXML is the media type used by the OBS API.
	contentTypeXML = "application/xml; charset=utf-8"
)

// Options configures the OBS client.
type Options struct {
	// Username is the OBS account used for HTTP basic authentication.
	Username string

	// Password is the password or token of the OBS account.
	Password string

	// APIURL is the base URL of the OBS API. Defaults to DefaultAPIURL.
	APIURL string

	// Dry prevents mutating requests from being sent. Read operations are still
	// executed, and mutations are still locally validated and prepared.
	Dry bool

	// Timeout is the timeout of the default HTTP client. Ignored when the client
	// is provided via NewWithClient. Defaults to DefaultTimeout.
	Timeout time.Duration
}

// DefaultOptions returns options with commonly used settings.
func DefaultOptions() *Options {
	return &Options{
		APIURL:  DefaultAPIURL,
		Timeout: DefaultTimeout,
	}
}

// OBS is a client for the OBS API.
type OBS struct {
	client  *http.Client
	options *Options
}

// New creates an OBS client using the default HTTP client.
func New(options *Options) *OBS {
	return NewWithClient(options, nil)
}

// NewWithClient creates an OBS client using the provided HTTP client. A nil
// client is replaced by the default one. Unset fields of options are filled in
// with defaults. The options are copied, so the caller's struct is left alone.
func NewWithClient(options *Options, client *http.Client) *OBS {
	opts := &Options{}
	if options != nil {
		*opts = *options
	}

	if opts.APIURL == "" {
		opts.APIURL = DefaultAPIURL
	}

	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}

	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}

	return &OBS{
		client:  client,
		options: opts,
	}
}

// DryRun reports whether mutating calls are suppressed.
func (o *OBS) DryRun() bool {
	return o.options.Dry
}

// APIURL returns the base URL of the OBS API used by this client.
func (o *OBS) APIURL() string {
	return o.options.APIURL
}

// get executes a GET request and decodes the response body into out.
func (o *OBS) get(ctx context.Context, out any, query url.Values, pathElements ...string) error {
	return o.do(ctx, http.MethodGet, nil, out, query, pathElements...)
}

// put executes a PUT request with payload as the request body.
func (o *OBS) put(ctx context.Context, payload any, pathElements ...string) error {
	return o.do(ctx, http.MethodPut, payload, nil, nil, pathElements...)
}

// delete executes a DELETE request.
func (o *OBS) delete(ctx context.Context, pathElements ...string) error {
	return o.do(ctx, http.MethodDelete, nil, nil, nil, pathElements...)
}

// do executes a request against the OBS API. It is the single place where dry
// mode is enforced: a mutating request is prepared and validated, but not sent.
func (o *OBS) do(ctx context.Context, method string, payload, out any, query url.Values, pathElements ...string) error {
	endpoint, err := url.JoinPath(o.options.APIURL, pathElements...)
	if err != nil {
		return fmt.Errorf("building request URL: %w", err)
	}

	body := &bytes.Buffer{}

	if payload != nil {
		if err := xml.NewEncoder(body).Encode(payload); err != nil {
			return fmt.Errorf("marshalling request body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return fmt.Errorf("creating %s request: %w", method, err)
	}

	if len(query) > 0 {
		req.URL.RawQuery = query.Encode()
	}

	if o.options.Username != "" || o.options.Password != "" {
		req.SetBasicAuth(o.options.Username, o.options.Password)
	}

	req.Header.Set("Accept", contentTypeXML)

	if payload != nil {
		req.Header.Set("Content-Type", contentTypeXML)
	}

	if method != http.MethodGet && o.options.Dry {
		return nil
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("executing %s request: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newAPIError(resp)
	}

	if out == nil {
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return fmt.Errorf("reading response: %w", err)
		}

		return nil
	}

	if err := xml.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	return nil
}
