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
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testBuilderProjectName = "isv:kubernetes:core:stable:v1.34:build"
	testCoreProjectName    = "isv:kubernetes:core"
	testPackageName        = "kubelet"
	testPathChangingName   = "../other"
	testUsername           = "k8s-test"
	testPassword           = "hunter2"
)

// recordedRequest captures the parts of a request the tests assert on. The
// request body is read eagerly, because it is not readable any more once the
// request has been handled.
type recordedRequest struct {
	Method string
	URL    string
	Body   string
	Header http.Header
}

// fakeClient is an http.RoundTripper returning canned responses while
// recording every request it receives.
type fakeClient struct {
	statusCode   int
	body         string
	err          error
	requests     []recordedRequest
	responseBody io.ReadCloser
}

func (f *fakeClient) RoundTrip(req *http.Request) (*http.Response, error) {
	body := ""

	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}

		body = string(raw)
	}

	f.requests = append(f.requests, recordedRequest{
		Method: req.Method,
		URL:    req.URL.String(),
		Body:   body,
		Header: req.Header.Clone(),
	})

	if f.err != nil {
		return nil, f.err
	}

	statusCode := f.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	responseBody := io.NopCloser(strings.NewReader(f.body))
	if f.responseBody != nil {
		responseBody = f.responseBody
	}

	return &http.Response{
		StatusCode: statusCode,
		Body:       responseBody,
		Request:    req,
	}, nil
}

// newTestOBS returns an OBS client backed by the given fake.
func newTestOBS(fake *fakeClient, dry bool) *OBS {
	return NewWithClient(&Options{
		Username: testUsername,
		Password: testPassword,
		APIURL:   DefaultAPIURL,
		Dry:      dry,
	}, fake.httpClient())
}

// httpClient wraps the fake as the transport of an http.Client.
func (f *fakeClient) httpClient() *http.Client {
	return &http.Client{Transport: f}
}

func TestGetProjectMeta(t *testing.T) {
	fake := &fakeClient{body: string(readFixture(t, "project_builder.xml"))}
	obs := newTestOBS(fake, false)

	project, err := obs.GetProjectMeta(t.Context(), testBuilderProjectName)
	require.NoError(t, err)
	assert.Equal(t, testBuilderProjectName, project.Name)

	require.Len(t, fake.requests, 1)
	request := fake.requests[0]
	assert.Equal(t, http.MethodGet, request.Method)
	assert.Equal(
		t,
		"https://api.opensuse.org/source/isv:kubernetes:core:stable:v1.34:build/_meta",
		request.URL,
	)
	assert.Equal(t, contentTypeXML, request.Header.Get("Accept"))

	username, password, ok := (&http.Request{Header: request.Header}).BasicAuth()
	assert.True(t, ok)
	assert.Equal(t, testUsername, username)
	assert.Equal(t, testPassword, password)
}

func TestGetProjectMetaNotFound(t *testing.T) {
	fake := &fakeClient{
		statusCode: http.StatusNotFound,
		body:       string(readFixture(t, "status_unknown_project.xml")),
	}

	_, err := newTestOBS(fake, false).GetProjectMeta(t.Context(), "isv:kubernetes:doesnotexist")
	require.Error(t, err)
	assert.True(t, IsNotFound(err), "expected a not found error, got %v", err)

	apiErr := &APIError{}
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.HTTPStatusCode)
	assert.Equal(t, StatusCodeUnknownProject, apiErr.OBSStatusCode)
	assert.Equal(t, "Project not found: isv:kubernetes:doesnotexist", apiErr.Message)
}

func TestIsNotFoundOtherErrors(t *testing.T) {
	assert.False(t, IsNotFound(nil))
	assert.False(t, IsNotFound(errors.New("boom")))
	assert.False(t, IsNotFound(&APIError{HTTPStatusCode: http.StatusInternalServerError}))

	// A 404 without a status document did not come from OBS: a wrong API URL
	// or a mistyped endpoint is answered by the web server with its own error
	// page. Reporting it as missing would make a caller that creates what it
	// cannot find try to create everything.
	assert.False(t, IsNotFound(&APIError{HTTPStatusCode: http.StatusNotFound}))
	assert.False(t, IsNotFound(&APIError{
		HTTPStatusCode: http.StatusNotFound,
		Message:        "Error 404 Not Found",
	}))

	// An OBS status code only counts together with a 404.
	assert.False(t, IsNotFound(&APIError{
		HTTPStatusCode: http.StatusInternalServerError,
		OBSStatusCode:  StatusCodeUnknownProject,
	}))
	assert.True(t, IsNotFound(&APIError{
		HTTPStatusCode: http.StatusNotFound,
		OBSStatusCode:  StatusCodeUnknownProject,
	}))
	assert.True(t, IsNotFound(&APIError{
		HTTPStatusCode: http.StatusNotFound,
		OBSStatusCode:  StatusCodeUnknownPackage,
	}))
}

func TestIsUnauthorized(t *testing.T) {
	assert.False(t, IsUnauthorized(nil))
	assert.False(t, IsUnauthorized(errors.New("boom")))
	assert.False(t, IsUnauthorized(&APIError{HTTPStatusCode: http.StatusNotFound}))
	assert.True(t, IsUnauthorized(&APIError{HTTPStatusCode: http.StatusUnauthorized}))

	// OBS answers an accepted but insufficient credential with 403, which is a
	// different problem from a rejected one.
	assert.False(t, IsUnauthorized(&APIError{HTTPStatusCode: http.StatusForbidden}))
}

func TestIsForbidden(t *testing.T) {
	assert.False(t, IsForbidden(nil))
	assert.False(t, IsForbidden(errors.New("boom")))
	assert.False(t, IsForbidden(&APIError{HTTPStatusCode: http.StatusUnauthorized}))
	assert.True(t, IsForbidden(&APIError{HTTPStatusCode: http.StatusForbidden}))
	assert.True(t, IsForbidden(&APIError{
		HTTPStatusCode: http.StatusForbidden,
		OBSStatusCode:  "change_project_no_permission",
	}))
}

// TestAPIErrorWithoutStatusDocument pins that a response the OBS application
// never produced still yields the status code that explains it. An
// unauthenticated request is answered by the web server in front of OBS with
// an HTML page, which must not be reported as an XML decoding failure.
func TestAPIErrorWithoutStatusDocument(t *testing.T) {
	for name, testCase := range map[string]struct {
		statusCode int
		body       string
		message    string
		expected   string
	}{
		"html error page is reduced to its title": {
			statusCode: http.StatusUnauthorized,
			body: `<?xml version="1.0" encoding="UTF-8"?><html><head>` +
				"<title>Authentication required!</title>" +
				`<style>body { color: #000 }</style></head><body>` +
				"<h1>Authentication required!</h1></body></html>",
			message:  "Authentication required!",
			expected: "HTTP 401 Unauthorized: Authentication required!",
		},
		"html entities in the title are decoded": {
			statusCode: http.StatusBadRequest,
			body:       "<html><head><title>Bad &amp; broken</title></head></html>",
			message:    "Bad & broken",
			expected:   "HTTP 400 Bad Request: Bad & broken",
		},
		"html page without a title": {
			statusCode: http.StatusForbidden,
			body:       "<html><body><h1>go away</h1></body></html>",
			expected:   "HTTP 403 Forbidden",
		},
		"empty body": {
			statusCode: http.StatusBadGateway,
			expected:   "HTTP 502 Bad Gateway",
		},
		"plain text body": {
			statusCode: http.StatusServiceUnavailable,
			body:       "  the service is\n  down for maintenance  ",
			message:    "the service is down for maintenance",
			expected:   "HTTP 503 Service Unavailable: the service is down for maintenance",
		},
		"unknown status code": {
			statusCode: 599,
			expected:   "HTTP 599",
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeClient{statusCode: testCase.statusCode, body: testCase.body}

			_, err := newTestOBS(fake, false).GetProjectMeta(t.Context(), "isv:kubernetes")
			require.Error(t, err)

			apiErr := &APIError{}
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, testCase.statusCode, apiErr.HTTPStatusCode)
			assert.Empty(t, apiErr.OBSStatusCode)
			assert.Equal(t, testCase.message, apiErr.Message)
			assert.Equal(t, testCase.expected, apiErr.Error())

			// Whatever the summary kept, the body is available in full.
			assert.Equal(t, testCase.body, string(apiErr.Body))
		})
	}
}

// TestAPIErrorKeepsBodyInFull pins that a large body reaches both the message
// and APIError.Body untouched, which is what makes an unexpected failure
// diagnosable from what the server actually sent.
func TestAPIErrorKeepsBodyInFull(t *testing.T) {
	body := strings.Repeat("a", 32<<10)
	fake := &fakeClient{statusCode: http.StatusInternalServerError, body: body}

	_, err := newTestOBS(fake, false).GetProjectMeta(t.Context(), "isv:kubernetes")
	require.Error(t, err)

	apiErr := &APIError{}
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, body, apiErr.Message)
	assert.Equal(t, body, string(apiErr.Body))
	assert.Len(t, apiErr.Body, 32<<10)
}

// TestAPIErrorBodyIsBounded pins that reading the body is bounded, so that a
// pathological response cannot exhaust memory on a path that runs on every
// failed request.
func TestAPIErrorBodyIsBounded(t *testing.T) {
	fake := &fakeClient{
		statusCode: http.StatusInternalServerError,
		body:       strings.Repeat("a", maxErrorBodySize+4096),
	}

	_, err := newTestOBS(fake, false).GetProjectMeta(t.Context(), "isv:kubernetes")
	require.Error(t, err)

	apiErr := &APIError{}
	require.ErrorAs(t, err, &apiErr)
	assert.Len(t, apiErr.Body, maxErrorBodySize)
}

func TestSummarizeBodyProducesValidUTF8(t *testing.T) {
	message := summarizeBody([]byte("a é suffix"))
	assert.Equal(t, "a é suffix", message)
	assert.True(t, utf8.ValidString(message))

	message = summarizeBody([]byte{'a', 0xff, 'b'})
	assert.Equal(t, "ab", message)
	assert.True(t, utf8.ValidString(message))
}

// TestAPIErrorWithStatusDocument pins the rendering of a regular API error.
func TestAPIErrorWithStatusDocument(t *testing.T) {
	err := &APIError{
		HTTPStatusCode: http.StatusNotFound,
		OBSStatusCode:  StatusCodeUnknownProject,
		Message:        "Project not found: isv:kubernetes:doesnotexist",
	}

	assert.Equal(
		t,
		"HTTP 404 Not Found: unknown_project: Project not found: isv:kubernetes:doesnotexist",
		err.Error(),
	)
}

func TestPutProjectMeta(t *testing.T) {
	fake := &fakeClient{}
	obs := newTestOBS(fake, false)

	project := &Project{
		Name:  testCoreProjectName,
		Title: "Kubernetes Core Packages",
		Build: Flag{{Action: FlagActionDisable}},
	}
	require.NoError(t, obs.PutProjectMeta(t.Context(), project))

	require.Len(t, fake.requests, 1)
	request := fake.requests[0]
	assert.Equal(t, http.MethodPut, request.Method)
	assert.Equal(t, "https://api.opensuse.org/source/isv:kubernetes:core/_meta", request.URL)
	assert.Equal(t, contentTypeXML, request.Header.Get("Content-Type"))
	assert.Contains(t, request.Body, "<title>Kubernetes Core Packages</title>")
	assert.Contains(t, request.Body, "<build><disable></disable></build>")
}

func TestPutProjectMetaValidation(t *testing.T) {
	fake := &fakeClient{}
	obs := newTestOBS(fake, false)

	require.ErrorContains(t, obs.PutProjectMeta(t.Context(), nil), "must not be nil")
	require.ErrorContains(t, obs.PutProjectMeta(t.Context(), &Project{}), "name must not be empty")
	assert.Empty(t, fake.requests)
}

func TestOperationsRejectEmptyNames(t *testing.T) {
	testcases := []struct {
		name string
		run  func(context.Context, *OBS) error
	}{
		{
			name: "get project",
			run: func(ctx context.Context, obs *OBS) error {
				_, err := obs.GetProjectMeta(ctx, "")

				return err
			},
		},
		{
			name: "delete project",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.DeleteProject(ctx, "")
			},
		},
		{
			name: "list packages",
			run: func(ctx context.Context, obs *OBS) error {
				_, err := obs.ListPackages(ctx, "")

				return err
			},
		},
		{
			name: "get package without project",
			run: func(ctx context.Context, obs *OBS) error {
				_, err := obs.GetPackageMeta(ctx, "", testPackageName)

				return err
			},
		},
		{
			name: "get package without package",
			run: func(ctx context.Context, obs *OBS) error {
				_, err := obs.GetPackageMeta(ctx, testCoreProjectName, "")

				return err
			},
		},
		{
			name: "put package",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.PutPackageMeta(ctx, &Package{Name: testPackageName})
			},
		},
		{
			name: "delete package without project",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.DeletePackage(ctx, "", testPackageName)
			},
		},
		{
			name: "delete package without package",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.DeletePackage(ctx, testCoreProjectName, "")
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeClient{}

			require.ErrorContains(t, tc.run(t.Context(), newTestOBS(fake, false)), "name must not be empty")
			assert.Empty(t, fake.requests)
		})
	}
}

func TestOperationsRejectPathChangingNames(t *testing.T) {
	testcases := []struct {
		name string
		run  func(context.Context, *OBS) error
	}{
		{
			name: "get project",
			run: func(ctx context.Context, obs *OBS) error {
				_, err := obs.GetProjectMeta(ctx, testPathChangingName)

				return err
			},
		},
		{
			name: "put project",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.PutProjectMeta(ctx, &Project{Name: testPathChangingName})
			},
		},
		{
			name: "delete project",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.DeleteProject(ctx, testPathChangingName)
			},
		},
		{
			name: "list packages",
			run: func(ctx context.Context, obs *OBS) error {
				_, err := obs.ListPackages(ctx, testPathChangingName)

				return err
			},
		},
		{
			name: "get package with bad project",
			run: func(ctx context.Context, obs *OBS) error {
				_, err := obs.GetPackageMeta(ctx, testPathChangingName, testPackageName)

				return err
			},
		},
		{
			name: "get package with bad package",
			run: func(ctx context.Context, obs *OBS) error {
				_, err := obs.GetPackageMeta(ctx, testCoreProjectName, testPathChangingName)

				return err
			},
		},
		{
			name: "put package with bad project",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.PutPackageMeta(ctx, &Package{Name: testPackageName, Project: testPathChangingName})
			},
		},
		{
			name: "put package with bad package",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.PutPackageMeta(ctx, &Package{Name: testPathChangingName, Project: testCoreProjectName})
			},
		},
		{
			name: "delete package with bad project",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.DeletePackage(ctx, testPathChangingName, testPackageName)
			},
		},
		{
			name: "delete package with bad package",
			run: func(ctx context.Context, obs *OBS) error {
				return obs.DeletePackage(ctx, testCoreProjectName, testPathChangingName)
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeClient{}

			require.ErrorContains(t, tc.run(t.Context(), newTestOBS(fake, false)), "invalid")
			assert.Empty(t, fake.requests)
		})
	}
}

func TestListPackages(t *testing.T) {
	fake := &fakeClient{body: string(readFixture(t, "directory_packages.xml"))}
	obs := newTestOBS(fake, false)

	packages, err := obs.ListPackages(t.Context(), testBuilderProjectName)
	require.NoError(t, err)

	// Release copies are reported as-is; filtering is up to the caller.
	assert.Contains(t, packages, testPackageName)
	assert.Contains(t, packages, "kubernetes-cni.20250828170903")

	require.Len(t, fake.requests, 1)
	assert.Equal(
		t,
		"https://api.opensuse.org/source/isv:kubernetes:core:stable:v1.34:build",
		fake.requests[0].URL,
	)
}

func TestListSubprojects(t *testing.T) {
	fake := &fakeClient{body: `<collection matches="2">` +
		`<project name="isv:kubernetes:core"/><project name="isv:kubernetes:addons"/></collection>`}
	obs := newTestOBS(fake, false)

	projects, err := obs.ListSubprojects(t.Context(), "isv:kubernetes")
	require.NoError(t, err)
	assert.Equal(t, []string{"isv:kubernetes:core", "isv:kubernetes:addons"}, projects)

	require.Len(t, fake.requests, 1)
	request := fake.requests[0]
	assert.Contains(t, request.URL, "https://api.opensuse.org/search/project/id?")

	// The trailing colon keeps a prefix such as isv:kubernetes from matching
	// isv:kubernetesfoo, and v1.3 from matching v1.30.
	assert.Contains(t, request.URL, "match=starts-with%28%40name%2C%27isv%3Akubernetes%3A%27%29")
}

func TestListSubprojectsRejectsBadProjectName(t *testing.T) {
	fake := &fakeClient{}
	obs := newTestOBS(fake, false)

	_, err := obs.ListSubprojects(t.Context(), "")
	require.ErrorContains(t, err, "project name must not be empty")

	// The name is interpolated into an XPath string literal.
	_, err = obs.ListSubprojects(t.Context(), "isv:kubernetes')]|//*[")
	require.ErrorContains(t, err, "invalid project name")

	assert.Empty(t, fake.requests)
}

func TestPackageOperations(t *testing.T) {
	fake := &fakeClient{body: string(readFixture(t, "package_minimal.xml"))}
	obs := newTestOBS(fake, false)

	pkg, err := obs.GetPackageMeta(t.Context(), testBuilderProjectName, testPackageName)
	require.NoError(t, err)
	assert.Equal(t, testPackageName, pkg.Name)

	require.NoError(t, obs.PutPackageMeta(t.Context(), &Package{Name: testPackageName, Project: testBuilderProjectName}))
	require.NoError(t, obs.DeletePackage(t.Context(), testBuilderProjectName, testPackageName))

	require.Len(t, fake.requests, 3)
	assert.Equal(t, http.MethodGet, fake.requests[0].Method)
	assert.Equal(
		t,
		"https://api.opensuse.org/source/isv:kubernetes:core:stable:v1.34:build/kubelet/_meta",
		fake.requests[0].URL,
	)
	assert.Equal(t, http.MethodPut, fake.requests[1].Method)
	assert.Equal(
		t,
		"https://api.opensuse.org/source/isv:kubernetes:core:stable:v1.34:build/kubelet/_meta",
		fake.requests[1].URL,
	)
	assert.Equal(
		t,
		`<package name="kubelet" project="isv:kubernetes:core:stable:v1.34:build">`+
			`<title></title><description></description></package>`,
		strings.TrimSpace(fake.requests[1].Body),
	)
	assert.Equal(t, http.MethodDelete, fake.requests[2].Method)
	assert.Equal(
		t,
		"https://api.opensuse.org/source/isv:kubernetes:core:stable:v1.34:build/kubelet",
		fake.requests[2].URL,
	)
}

func TestPutPackageMetaRequiresProject(t *testing.T) {
	fake := &fakeClient{}
	obs := newTestOBS(fake, false)

	err := obs.PutPackageMeta(t.Context(), &Package{Name: testPackageName})
	require.ErrorContains(t, err, "project name must not be empty")
	assert.Empty(t, fake.requests)
}

func TestSuccessfulMutationDrainsResponseBody(t *testing.T) {
	responseBody := strings.NewReader(`<status code="ok"/>`)
	fake := &fakeClient{responseBody: io.NopCloser(responseBody)}

	require.NoError(t, newTestOBS(fake, false).DeleteProject(t.Context(), testCoreProjectName))
	assert.Zero(t, responseBody.Len())
}

// TestDryRunSuppressesMutations is the central guarantee of dry mode: reads are
// executed so that a caller can compute an accurate diff, while valid mutating
// calls are prepared but not sent.
func TestDryRunSuppressesMutations(t *testing.T) {
	fake := &fakeClient{body: string(readFixture(t, "project_builder.xml"))}
	obs := newTestOBS(fake, true)

	assert.True(t, obs.DryRun())

	_, err := obs.GetProjectMeta(t.Context(), testBuilderProjectName)
	require.NoError(t, err)
	assert.Len(t, fake.requests, 1, "reads must still be executed in dry mode")

	require.NoError(t, obs.PutProjectMeta(t.Context(), &Project{Name: testCoreProjectName}))
	require.NoError(t, obs.DeleteProject(t.Context(), testCoreProjectName))
	require.NoError(t, obs.PutPackageMeta(t.Context(), &Package{Name: testPackageName, Project: testCoreProjectName}))
	require.NoError(t, obs.DeletePackage(t.Context(), testCoreProjectName, testPackageName))

	assert.Len(t, fake.requests, 1, "no mutating request may be executed in dry mode")
}

// TestDryRunStillValidates ensures dry mode does not mask invalid input.
func TestDryRunStillValidates(t *testing.T) {
	obs := newTestOBS(&fakeClient{}, true)

	require.ErrorContains(t, obs.PutProjectMeta(t.Context(), &Project{}), "name must not be empty")
	require.ErrorContains(t, obs.PutProjectMeta(t.Context(), &Project{
		Name:  testCoreProjectName,
		Build: Flag{{Action: "bogus"}},
	}), `invalid flag action "bogus"`)
}

func TestNewAppliesDefaults(t *testing.T) {
	obs := New(nil)
	assert.Equal(t, DefaultAPIURL, obs.APIURL())
	assert.False(t, obs.DryRun())

	// The provided options must not be modified.
	opts := &Options{}
	obs = New(opts)
	assert.Empty(t, opts.APIURL)
	assert.Zero(t, opts.Timeout)
	assert.Equal(t, DefaultAPIURL, obs.APIURL())
}

func TestNewWithClientDefaultsNilClient(t *testing.T) {
	obs := NewWithClient(nil, nil)
	assert.NotNil(t, obs.client)
	assert.Equal(t, DefaultAPIURL, obs.APIURL())
	assert.Equal(t, DefaultTimeout, obs.client.Timeout)

	// A substituted client must still get the timeout, not an unbounded one.
	obs = NewWithClient(&Options{}, nil)
	assert.Equal(t, DefaultTimeout, obs.client.Timeout)

	// A provided client is used as-is, Options.Timeout does not apply.
	provided := &http.Client{Timeout: time.Second}
	obs = NewWithClient(&Options{Timeout: time.Hour}, provided)
	assert.Same(t, provided, obs.client)
	assert.Equal(t, time.Second, obs.client.Timeout)
}

func TestAnonymousClientOmitsAuthorizationHeader(t *testing.T) {
	fake := &fakeClient{body: string(readFixture(t, "project_builder.xml"))}
	obs := NewWithClient(nil, fake.httpClient())

	_, err := obs.GetProjectMeta(t.Context(), testBuilderProjectName)
	require.NoError(t, err)
	require.Len(t, fake.requests, 1)
	assert.Empty(t, fake.requests[0].Header.Get("Authorization"))
}

func TestTransportError(t *testing.T) {
	fake := &fakeClient{err: errors.New("connection refused")}

	_, err := newTestOBS(fake, false).GetProjectMeta(t.Context(), "isv:kubernetes")
	require.ErrorContains(t, err, "connection refused")
	assert.False(t, IsNotFound(err))
}

// TestContextIsPropagated ensures the caller's context reaches the transport.
func TestContextIsPropagated(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	obs := NewWithClient(&Options{}, &http.Client{})

	_, err := obs.GetProjectMeta(ctx, "isv:kubernetes")
	require.ErrorIs(t, err, context.Canceled)
}
