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
	"fmt"
)

// FlagAction is the action applied by a FlagRule.
type FlagAction string

const (
	// FlagActionEnable enables the flag for the scope of the rule.
	FlagActionEnable FlagAction = "enable"

	// FlagActionDisable disables the flag for the scope of the rule.
	FlagActionDisable FlagAction = "disable"
)

// FlagRule is a single enable or disable rule of a flag element, optionally
// scoped to a repository and/or an architecture.
type FlagRule struct {
	// Action is either FlagActionEnable or FlagActionDisable.
	Action FlagAction `json:"action" xml:"-"`

	// Repository scopes the rule to a single repository. Empty means all.
	Repository string `json:"repository,omitempty" xml:"repository,attr,omitempty"`

	// Arch scopes the rule to a single architecture. Empty means all.
	Arch string `json:"arch,omitempty" xml:"arch,attr,omitempty"`
}

// Flag is an ordered list of rules of a single OBS flag element, such as
// build, publish, useforbuild, debuginfo or binarydownload:
//
//	<build>
//	  <disable/>
//	  <enable repository="rpm"/>
//	  <disable repository="rpm" arch="s390x"/>
//	</build>
//
// Document order is preserved for stable round trips. OBS picks the effective
// rule by scope specificity, independently of that order. An empty Flag is
// omitted when marshalled, being meaningless to OBS.
type Flag []FlagRule

// MarshalXML implements xml.Marshaler.
func (f Flag) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	if err := encoder.EncodeToken(start); err != nil {
		return fmt.Errorf("encoding flag element %s: %w", start.Name.Local, err)
	}

	for _, rule := range f {
		if err := rule.marshalXML(encoder); err != nil {
			return err
		}
	}

	if err := encoder.EncodeToken(xml.EndElement{Name: start.Name}); err != nil {
		return fmt.Errorf("closing flag element %s: %w", start.Name.Local, err)
	}

	return nil
}

// UnmarshalXML implements xml.Unmarshaler. Elements other than enable and
// disable are skipped.
func (f *Flag) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	rules := Flag{}

	for {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decoding flag element %s: %w", start.Name.Local, err)
		}

		switch element := token.(type) {
		case xml.StartElement:
			if action := FlagAction(element.Name.Local); action == FlagActionEnable || action == FlagActionDisable {
				rules = append(rules, newFlagRule(action, element.Attr))
			}

			if err := decoder.Skip(); err != nil {
				return fmt.Errorf("skipping element %s: %w", element.Name.Local, err)
			}
		case xml.EndElement:
			if element.Name == start.Name {
				*f = rules

				return nil
			}
		}
	}
}

// marshalXML encodes the rule as an empty element named after its action.
func (r FlagRule) marshalXML(encoder *xml.Encoder) error {
	if r.Action != FlagActionEnable && r.Action != FlagActionDisable {
		return fmt.Errorf("invalid flag action %q, must be %q or %q", r.Action, FlagActionEnable, FlagActionDisable)
	}

	name := xml.Name{Local: string(r.Action)}
	attrs := make([]xml.Attr, 0, 2)

	if r.Repository != "" {
		attrs = append(attrs, xml.Attr{Name: xml.Name{Local: "repository"}, Value: r.Repository})
	}

	if r.Arch != "" {
		attrs = append(attrs, xml.Attr{Name: xml.Name{Local: "arch"}, Value: r.Arch})
	}

	if err := encoder.EncodeToken(xml.StartElement{Name: name, Attr: attrs}); err != nil {
		return fmt.Errorf("encoding flag rule %s: %w", r.Action, err)
	}

	if err := encoder.EncodeToken(xml.EndElement{Name: name}); err != nil {
		return fmt.Errorf("closing flag rule %s: %w", r.Action, err)
	}

	return nil
}

// newFlagRule builds a FlagRule from an action and the attributes of the
// corresponding XML element.
func newFlagRule(action FlagAction, attrs []xml.Attr) FlagRule {
	rule := FlagRule{Action: action}

	for _, attr := range attrs {
		switch attr.Name.Local {
		case "repository":
			rule.Repository = attr.Value
		case "arch":
			rule.Arch = attr.Value
		}
	}

	return rule
}
