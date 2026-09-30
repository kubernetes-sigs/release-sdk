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
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testArchitectureS390X = "s390x"
	testArchitectureX8664 = "x86_64"
	testRPMRepository     = "rpm"
)

// flagHolder wraps a Flag so that it can be marshalled on its own. The Flag
// field deliberately carries no omitempty, so that empty flags are observable.
type flagHolder struct {
	XMLName xml.Name `xml:"holder"`
	Build   Flag     `xml:"build"`
}

func TestFlagUnmarshalXML(t *testing.T) {
	testcases := []struct {
		name     string
		input    string
		expected Flag
	}{
		{
			name:     "single unscoped disable",
			input:    `<build><disable/></build>`,
			expected: Flag{{Action: FlagActionDisable}},
		},
		{
			name:     "single unscoped enable",
			input:    `<build><enable/></build>`,
			expected: Flag{{Action: FlagActionEnable}},
		},
		{
			name:  "ordered scoped rules",
			input: `<build><disable/><enable repository="rpm"/><disable repository="rpm" arch="s390x"/></build>`,
			expected: Flag{
				{Action: FlagActionDisable},
				{Action: FlagActionEnable, Repository: testRPMRepository},
				{Action: FlagActionDisable, Repository: testRPMRepository, Arch: testArchitectureS390X},
			},
		},
		{
			name:     "arch only scoping",
			input:    `<build><enable arch="x86_64"/></build>`,
			expected: Flag{{Action: FlagActionEnable, Arch: testArchitectureX8664}},
		},
		{
			name:     "empty flag element",
			input:    `<build></build>`,
			expected: Flag{},
		},
		{
			name:     "unknown elements are skipped",
			input:    `<build><somethingelse foo="bar"/><disable/></build>`,
			expected: Flag{{Action: FlagActionDisable}},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			flag := Flag{}
			require.NoError(t, xml.Unmarshal([]byte(tc.input), &flag))
			assert.Equal(t, tc.expected, flag)
		})
	}
}

func TestFlagMarshalXML(t *testing.T) {
	testcases := []struct {
		name     string
		flag     Flag
		expected string
	}{
		{
			name:     "single unscoped disable",
			flag:     Flag{{Action: FlagActionDisable}},
			expected: `<holder><build><disable></disable></build></holder>`,
		},
		{
			name: "ordered scoped rules keep their order",
			flag: Flag{
				{Action: FlagActionDisable},
				{Action: FlagActionEnable, Repository: testRPMRepository},
				{Action: FlagActionDisable, Repository: testRPMRepository, Arch: testArchitectureS390X},
			},
			expected: `<holder><build><disable></disable><enable repository="rpm"></enable>` +
				`<disable repository="rpm" arch="s390x"></disable></build></holder>`,
		},
		{
			name:     "empty flag emits an empty element",
			flag:     Flag{},
			expected: `<holder><build></build></holder>`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := xml.Marshal(&flagHolder{Build: tc.flag})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(encoded))
		})
	}
}

func TestFlagMarshalXMLInvalidAction(t *testing.T) {
	_, err := xml.Marshal(&flagHolder{Build: Flag{{Action: "bogus"}}})
	require.ErrorContains(t, err, `invalid flag action "bogus"`)
}

// TestFlagOmittedWhenEmpty documents that a flag without rules carries no
// meaning to OBS and is therefore not written out.
func TestFlagOmittedWhenEmpty(t *testing.T) {
	encoded, err := xml.Marshal(&Project{Name: "test", Build: Flag{}})
	require.NoError(t, err)

	assert.NotContains(t, string(encoded), "<build>")
}
