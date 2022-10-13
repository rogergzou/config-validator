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

// Package armtarget is a constraint framework target for config-validator to use for integrating with the opa constraint framework.
package armtarget

import (
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/pkg/errors"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Name is the target name for ARMTarget
const Name = "arm.policy.azure.com"

// ARMTarget is the constraint framework target for config-validator
type ARMTarget struct {
}

var _ client.TargetHandler = &ARMTarget{}

// New returns a new ARMTarget
func New() *ARMTarget {
	return &ARMTarget{}
}

// MatchSchema implements client.MatchSchemaProvider
func (g *ARMTarget) MatchSchema() apiextensions.JSONSchemaProps {
	schema := apiextensions.JSONSchemaProps{
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
	fmt.Println("==========ARM SCHEMA==========")
	fmt.Println(schema)
	fmt.Println("==========END ARM SCHEMA==========")
	return schema
}

// GetName implements client.TargetHandler
func (g *ARMTarget) GetName() string {
	fmt.Println("==========ARM GetName==========")
	return Name
}

// Library implements client.TargetHandler
func (g *ARMTarget) Library() *template.Template {
	fmt.Println("==========ARM Library==========")
	return libraryTemplate
}

// ProcessData implements client.TargetHandler
func (g *ARMTarget) ProcessData(obj interface{}) (bool, string, interface{}, error) {
	fmt.Println("==========ARM ProcessData==========")
	return false, "", nil, errors.Errorf("Storing data for referential constraint eval is not supported at this time.")
}

// HandleReview implements client.TargetHandler
func (g *ARMTarget) HandleReview(obj interface{}) (bool, interface{}, error) {
	fmt.Println("==========ARM HandleReview==========")
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
		fmt.Println(resource)
		return true, resource, nil
	}
	return false, nil, nil
}

// HandleViolation implements client.TargetHandler
func (g *ARMTarget) HandleViolation(result *types.Result) error {
	fmt.Println("==========ARM HandleViolation==========")
	result.Resource = result.Review
	fmt.Println(result)
	fmt.Println(result.Review)
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
func (g *ARMTarget) ValidateConstraint(constraint *unstructured.Unstructured) error {
	fmt.Println("==========ARM ValidateConstraint==========")
	fmt.Println(constraint.Object)
	includes, found, err := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "addresses")
	fmt.Println("INCLUDES")
	fmt.Println(includes)
	fmt.Println("FOUND")
	fmt.Println(found)
	fmt.Println("ERR")
	fmt.Println(err)
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
