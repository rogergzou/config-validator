// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tftarget is a constraint framework target for config-validator to use for integrating with the opa constraint framework.
package tftarget

import (
	"regexp"
	"strings"
	"text/template"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/pkg/errors"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Name is the target name for TFTarget
const Name = "validation.resourcechange.terraform.cloud.google.com"

// TFTarget is the constraint framework target for config-validator
type TFTarget struct {
}

var _ client.TargetHandler = &TFTarget{}

// New returns a new TFTarget
func New() *TFTarget {
	return &TFTarget{}
}

// MatchSchema implements client.MatchSchemaProvider
func (g *TFTarget) MatchSchema() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"addresses": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "string",
					},
				},
			},
			"excludedAddresses": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "string",
					},
				},
			},
		},
	}
}

// GetName implements client.TargetHandler
func (g *TFTarget) GetName() string {
	return Name
}

// Library implements client.TargetHandler
func (g *TFTarget) Library() *template.Template {
	return libraryTemplate
}

// ProcessData implements client.TargetHandler
func (g *TFTarget) ProcessData(obj interface{}) (bool, string, interface{}, error) {
	return false, "", nil, errors.Errorf("Storing data for referential constraint eval is not supported at this time.")
}

// HandleReview implements client.TargetHandler
func (g *TFTarget) HandleReview(obj interface{}) (bool, interface{}, error) {
	switch resource := obj.(type) {
	case map[string]interface{}:
		if _, found, err := unstructured.NestedString(resource, "name"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedString(resource, "address"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedMap(resource, "change"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedString(resource, "type"); !found || err != nil {
			return false, nil, err
		}
		return true, resource, nil
	}
	return false, nil, nil
}

// HandleViolation implements client.TargetHandler
func (g *TFTarget) HandleViolation(result *types.Result) error {
	result.Resource = result.Review
	return nil
}

var partRegex = regexp.MustCompile(`[\w.\-_\[\]\d]+`)

// checkPathGlob
func checkPathGlob(expression string) error {
	// check for path components / numbers
	parts := strings.Split(expression, ".")
	for i := 0; i < len(parts); i++ {
		item := parts[i]
		switch {
		case item == "*":
		case item == "**":
		case partRegex.MatchString(item):
		default:
			return errors.Errorf("unexpected item %s element %d in %s", item, i, expression)
		}
	}
	return nil
}

func checkPathGlobs(rs []string) error {
	for idx, r := range rs {
		if err := checkPathGlob(r); err != nil {
			return errors.Wrapf(err, "idx: %d", idx)
		}
	}
	return nil
}

// ValidateConstraint implements client.TargetHandler
func (g *TFTarget) ValidateConstraint(constraint *unstructured.Unstructured) error {
	includes, found, err := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "addresses")
	if err != nil {
		return errors.Errorf("invalid spec.match.addresses: %s", err)
	}
	if found {
		if err := checkPathGlobs(includes); err != nil {
			return errors.Wrapf(err, "invalid glob in target")
		}
	}
	excludes, found, err := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "excludedAddresses")
	if err != nil {
		return errors.Errorf("invalid spec.match.excludedAddresses: %s", err)
	}
	if found {
		if err := checkPathGlobs(excludes); err != nil {
			return errors.Wrapf(err, "invalid glob in exclude")
		}
	}
	return nil
}
