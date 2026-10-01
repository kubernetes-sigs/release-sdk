/*
Copyright 2023 The Kubernetes Authors.

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
	"encoding/xml"
	"errors"
	"html"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// OBS status codes that are relevant for control flow. OBS returns them in the
// code attribute of the status document accompanying a 404 response.
const (
	// StatusCodeUnknownProject is returned when the requested project does not exist.
	StatusCodeUnknownProject = "unknown_project"

	// StatusCodeUnknownPackage is returned when the requested package does not exist.
	StatusCodeUnknownPackage = "unknown_package"
)

// Status is the status document returned by the OBS API. It is used both for
// error responses and for plain acknowledgements.
type Status struct {
	XMLName xml.Name `json:"-"       xml:"status"`
	Code    string   `json:"code"    xml:"code,attr"`
	Summary string   `json:"summary" xml:"summary"`
}

// APIError is returned for every unsuccessful OBS API response.
type APIError struct {
	// HTTPStatusCode is the HTTP status code of the response.
	HTTPStatusCode int

	// OBSStatusCode is the code attribute of the returned status document.
	// Empty when the body is not a status document, which is the case when
	// the web server in front of OBS answered the request itself.
	OBSStatusCode string

	// Message is the summary of the returned status document, or a
	// description derived from the body when there is none.
	Message string

	// Body is the response body as received, for diagnosing a failure that
	// Message does not explain.
	Body []byte
}

// Error implements the error interface. Only the parts that carry information
// are rendered.
func (e *APIError) Error() string {
	message := "HTTP " + strconv.Itoa(e.HTTPStatusCode)

	if text := http.StatusText(e.HTTPStatusCode); text != "" {
		message += " " + text
	}

	if e.OBSStatusCode != "" {
		message += ": " + e.OBSStatusCode
	}

	if e.Message != "" {
		message += ": " + e.Message
	}

	return message
}

// NotFound reports whether the error signals a missing project or package.
//
// A bare 404 does not qualify: without a status document the request never
// reached OBS, so treating it as missing would make a caller that creates what
// it cannot find try to create everything.
func (e *APIError) NotFound() bool {
	if e.HTTPStatusCode != http.StatusNotFound {
		return false
	}

	return e.OBSStatusCode == StatusCodeUnknownProject ||
		e.OBSStatusCode == StatusCodeUnknownPackage
}

// Unauthorized reports whether the error signals missing or rejected
// credentials.
func (e *APIError) Unauthorized() bool {
	return e.HTTPStatusCode == http.StatusUnauthorized
}

// Forbidden reports whether the error signals that the credentials were
// accepted but do not permit the request.
func (e *APIError) Forbidden() bool {
	return e.HTTPStatusCode == http.StatusForbidden
}

// IsNotFound reports whether the given error signals a missing project or
// package. See APIError.NotFound for why a bare 404 does not qualify.
func IsNotFound(err error) bool {
	apiErr := &APIError{}
	if !errors.As(err, &apiErr) {
		return false
	}

	return apiErr.NotFound()
}

// IsUnauthorized reports whether the given error signals that the credentials
// are missing or wrong. Credentials that are accepted but insufficient give
// IsForbidden instead.
func IsUnauthorized(err error) bool {
	apiErr := &APIError{}
	if !errors.As(err, &apiErr) {
		return false
	}

	return apiErr.Unauthorized()
}

// IsForbidden reports whether the given error signals that the credentials were
// accepted but do not permit the request.
func IsForbidden(err error) bool {
	apiErr := &APIError{}
	if !errors.As(err, &apiErr) {
		return false
	}

	return apiErr.Forbidden()
}

// maxErrorBodySize bounds how much of an unsuccessful response is read into
// memory, so that a pathological one cannot exhaust it.
const maxErrorBodySize = 1 << 20 // 1 MiB

// newAPIError builds an APIError from an unsuccessful response. It consumes the
// response body, which the caller is still responsible for closing.
//
// A body that is not a status document must not become an XML decoding error:
// the web server in front of OBS rejects some requests itself, an
// unauthenticated one among them, and answers with an HTML page.
func newAPIError(resp *http.Response) *APIError {
	apiErr := &APIError{HTTPStatusCode: resp.StatusCode}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
	if err != nil {
		return apiErr
	}

	apiErr.Body = body

	status := Status{}
	if err := xml.Unmarshal(body, &status); err == nil {
		apiErr.OBSStatusCode = status.Code
		apiErr.Message = strings.TrimSpace(status.Summary)

		return apiErr
	}

	apiErr.Message = summarizeBody(body)

	return apiErr
}

var titleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// summarizeBody describes a body that is not a status document in one line.
// Markup is reduced to its title, the rest of an error page being styling.
func summarizeBody(body []byte) string {
	text := strings.TrimSpace(strings.ToValidUTF8(string(body), ""))
	if text == "" {
		return ""
	}

	if strings.HasPrefix(text, "<") {
		match := titleRegex.FindStringSubmatch(text)
		if match == nil {
			return ""
		}

		text = html.UnescapeString(match[1])
	}

	return strings.Join(strings.Fields(text), " ")
}
