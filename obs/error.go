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
	"fmt"
)

type Status struct {
	XMLName xml.Name `json:"status" xml:"status"`
	Code    string   `json:"code" xml:"code,attr"`
	Summary string   `json:"summary" xml:"summary"`
}

type APIError struct {
	HTTPStatusCode int
	OBSStatusCode  string
	Message        string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP status %d: %s (%s)", e.HTTPStatusCode, e.OBSStatusCode, e.Message)
}
