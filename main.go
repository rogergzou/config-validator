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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"text/template"

	// Constraint Framework Client
	cfclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	protoimpl "google.golang.org/protobuf/runtime/protoimpl"

	"github.com/GoogleCloudPlatform/config-validator/pkg/api/validator"
	"github.com/GoogleCloudPlatform/config-validator/pkg/gcv/configs"
	asset2 "github.com/GoogleCloudPlatform/config-validator/pkg/asset"
	"github.com/gogo/protobuf/jsonpb"
)

const defaultTargetName = "arm.policy.azure.com"

const defaultConstraintTemplateRego = `
package testconstraint

violation[{"msg": msg}] {
	input.parameters.kind == "VirtualMachine" 
    input.parameters.type == "Microsoft.Compute/virtualMachines"
	msg := input.parameters.msg
}
`

const testVersion = "v1beta1"
const testConstraintKind = "TestConstraint"

type Asset struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

type ReviewRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Assets Asset `protobuf:"bytes,1,rep,name=assets,proto3" json:"assets,omitempty"`
}

func newConstraintTemplate(targetName, rego string) *templates.ConstraintTemplate {
	// Building a correct constraint template is difficult based on the struct. It's easier
	// to reason about yaml files and rely on existing conversion code.
	fmt.Println("========== newConstraintTemplate ==========")
	fmt.Println(targetName)
	fmt.Println(rego)
	ctSpec := map[string]interface{}{
		"crd": map[string]interface{}{
			"spec": map[string]interface{}{
				"names": map[string]interface{}{
					"kind": testConstraintKind,
				},
				"validation": map[string]interface{}{
					"openAPIV3Schema": map[string]interface{}{},
				},
			},
		},
		"targets": []map[string]interface{}{
			{
				"target": targetName,
				"rego":   rego,
			},
		},
	}
	ct := map[string]interface{}{
		"apiVersion": fmt.Sprintf("templates.gatekeeper.sh/%s", testVersion),
		"kind":       "ConstraintTemplate",
		"metadata": map[string]interface{}{
			"name": strings.ToLower(testConstraintKind),
		},
		"spec": ctSpec,
	}

	config, err := configs.NewConfigurationFromContents([]*unstructured.Unstructured{&unstructured.Unstructured{Object: ct}}, []string{})
	if err != nil {
		// This represents an error in a test case
		panic(err)
	}

	var templates []*templates.ConstraintTemplate
	templates = append(templates, config.ARMTemplates...)
	templates = append(templates, config.GCPTemplates...)
	templates = append(templates, config.K8STemplates...)
	templates = append(templates, config.TFTemplates...)

	return templates[0]
}

// ARM LIBRARY TEMPLATE IMPLEMENTATION
/*
This comment puts the start of rego on line 10 so it's easier to do math when
it calls out the line number.
*/
const libraryTemplateSrc = `package target

matching_constraints[constraint] {
	asset := input.review
	constraint := {{.ConstraintsRoot}}[_][_]
	spec := object.get(constraint, "spec", {})
	match := object.get(spec, "match", {})

	# Try ancestries / excludedAncestries first, then
	# fall back to target / exclude.
	# Default matcher behavior is to match everything.
	ancestries := object.get(match, "ancestries", object.get(match, "target", ["**"]))
	ancestries_match := {asset.ancestry_path | path_matches(asset.ancestry_path, ancestries[_])}
	count(ancestries_match) != 0

	excluded_ancestries := object.get(match, "excludedAncestries", object.get(match, "exclude", []))
	excluded_ancestries_match := {asset.ancestry_path | path_matches(asset.ancestry_path, excluded_ancestries[_])}
	count(excluded_ancestries_match) == 0
}

# CAI Resource Types
matching_reviews_and_constraints[[review, constraint]] {
	# This code should not get executed as we do not yet support full audit mode
	review := {"msg": "unsupported operation"}
	constraint := {
		"msg": "unsupported operation",
		"kind": "invalid",
	}
}

autoreject_review[rejection] {
	false
	rejection := {
		"msg": "should not reach this", 
	}
}

# Match path and pattern
path_matches(path, pattern) {
	glob.match(pattern, ["/"], path)
}

########
# Util #
########
# get_default returns the value of an object's field or the provided default value.
# It avoids creating an undefined state when trying to access an object attribute that does
# not exist
get_default(object, field, _default) = output {
  has_field(object, field)
  output = object[field]
}

get_default(object, field, _default) = output {
  has_field(object, field) == false
  output = _default
}

# has_field returns whether an object has a field
has_field(object, field) = true {
  object[field]
}
# False is a tricky special case, as false responses would create an undefined document unless
# they are explicitly tested for
has_field(object, field) = true {
  object[field] == false
}
has_field(object, field) = false {
  not object[field]
  not object[field] == false
}

`

var libraryTemplate = template.Must(template.New("Library").Parse(libraryTemplateSrc))


// ARM TARGET HANDLER IMPLEMENTATION
// Name is the target name for ARMTarget
const Name = "arm.policy.azure.com"

// ARMTarget is the constraint framework target for CAI asset data
type ARMTarget struct {
}

var _ cfclient.TargetHandler = &ARMTarget{}

// New returns a new ARMTarget
func New() *ARMTarget {
	return &ARMTarget{}
}

// MatchSchema implements client.MatchSchemaProvider
func (g *ARMTarget) MatchSchema() apiextensions.JSONSchemaProps {
	schema := apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"target": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "string",
					},
				},
			},
			"exclude": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "string",
					},
				},
			},
			"ancestries": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "string",
					},
				},
			},
			"excludedAncestries": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "string",
					},
				},
			},
		},
	}

	return schema
}

// GetName implements client.TargetHandler
func (g *ARMTarget) GetName() string {
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
	return false, "", nil, errors.New("Storing data for referential constraint eval is not supported at this time.")
}

// HandleReview implements client.TargetHandler
func (g *ARMTarget) HandleReview(obj interface{}) (bool, interface{}, error) {
	fmt.Println("==========ARM HandleReview==========")
	switch asset := obj.(type) {
	case map[string]interface{}:
		if _, found, err := unstructured.NestedString(asset, "name"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedString(asset, "asset_type"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedString(asset, "ancestry_path"); !found || err != nil {
			return false, nil, err
		}
		_, foundResource, err := unstructured.NestedMap(asset, "resource")
		if err != nil {
			return false, nil, err
		}
		_, foundIam, err := unstructured.NestedMap(asset, "iam_policy")
		if err != nil {
			return false, nil, err
		}
		foundOrgPolicy := false
		if asset["org_policy"] != nil {
			foundOrgPolicy = true
		}
		_, foundAccessPolicy, err := unstructured.NestedMap(asset, "access_policy")
		if err != nil {
			return false, nil, err
		}
		_, foundAcessLevel, err := unstructured.NestedMap(asset, "access_level")
		if err != nil {
			return false, nil, err
		}
		_, foundServicePerimeter, err := unstructured.NestedMap(asset, "service_perimeter")
		if err != nil {
			return false, nil, err
		}

		if !foundIam && !foundResource && !foundOrgPolicy && !foundAccessPolicy && !foundAcessLevel && !foundServicePerimeter {
			return false, nil, nil
		}
		resourceTypes := 0
		if foundResource {
			resourceTypes++
		}
		if foundIam {
			resourceTypes++
		}
		if foundOrgPolicy {
			resourceTypes++
		}
		if foundAccessPolicy {
			resourceTypes++
		}
		if foundAcessLevel {
			resourceTypes++
		}
		if foundServicePerimeter {
			resourceTypes++
		}
		if resourceTypes > 1 {
			return false, nil, fmt.Errorf("malformed asset has more than one of: resource, iam policy, org policy, access context policy: %v", asset)
		}
		return true, asset, nil
	}
	return false, nil, nil
}

// handleAsset handles input from CAI assets as received via the gRPC interface.
func (g *ARMTarget) handleAsset(asset *validator.Asset) (bool, interface{}, error) {
	if asset.Resource == nil {
		return false, nil, fmt.Errorf("CAI asset's resource field is nil %s", asset)
	}
	asset2.CleanStructValue(asset.Resource.Data)
	m := &jsonpb.Marshaler{
		OrigName: true,
	}
	var buf bytes.Buffer
	if err := m.Marshal(&buf, asset); err != nil {
		return false, nil, fmt.Errorf("marshalling to json with asset %s: %v. %w", asset.Name, asset, err)
	}
	var f interface{}
	err := json.Unmarshal(buf.Bytes(), &f)
	if err != nil {
		return false, nil, fmt.Errorf("marshalling from json with asset %s: %v. %w", asset.Name, asset, err)
	}
	return true, f, nil
}

// HandleViolation implements client.TargetHandler
func (g *ARMTarget) HandleViolation(result *types.Result) error {
	fmt.Println("==========ARM HandleViolation==========")
	fmt.Println(result)
	fmt.Println(result.Review)
	result.Resource = result.Review
	return nil
}

/*
cases
organizations/*
organizations/[0-9]+/*
organizations/[0-9]+/folders/*
organizations/[0-9]+/folders/[0-9]+/*
organizations/[0-9]+/folders/[0-9]+/projects/*
organizations/[0-9]+/folders/[0-9]+/projects/[0-9]+
folders/*
folders/[0-9]+/*
folders/[0-9]+/projects/*
folders/[0-9]+/projects/[0-9]+
projects/*
projects/[0-9]+
*/

const (
	organization = "organizations"
	folder       = "folders"
	project      = "projects"
)

const (
	stateStart   = "stateStart"
	stateFolder  = "stateFolder"
	stateProject = "stateProject"
)

var numberRegex = regexp.MustCompile(`^[0-9]+\*{0,2}$`)

// From https://cloud.google.com/resource-manager/docs/creating-managing-projects:
// The project ID must be a unique string of 6 to 30 lowercase letters, digits, or hyphens. It must start with a letter, and cannot have a trailing hyphen.
var projectIDRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{5,27}[a-z0-9]$`)

// checkPathGlob
func checkPathGlob(expression string) error {
	// check for path components / numbers
	parts := strings.Split(expression, "/")
	state := stateStart
	for i := 0; i < len(parts); i++ {
		item := parts[i]
		switch {
		case item == organization:
			if state != stateStart {
				return fmt.Errorf("unexpected %s element %d in %s", item, i, expression)
			}
			state = stateFolder
		case item == folder:
			if state != stateStart && state != stateFolder {
				return fmt.Errorf("unexpected %s element %d in %s", item, i, expression)
			}
			state = stateFolder
		case item == project:
			state = stateProject
		case item == "*":
		case item == "**":
		case item == "unknown":
		case numberRegex.MatchString(item):
		case state == stateProject && projectIDRegex.MatchString(item):
		default:
			return fmt.Errorf("unexpected item %s element %d in %s", item, i, expression)
		}
	}
	return nil
}

func checkPathGlobs(rs []string) error {
	for idx, r := range rs {
		if err := checkPathGlob(r); err != nil {
			return fmt.Errorf("idx [%d]: %w", idx, err)
		}
	}
	return nil
}

// ValidateConstraint implements client.TargetHandler
func (g *ARMTarget) ValidateConstraint(constraint *unstructured.Unstructured) error {
	fmt.Println("==========ARM ValidateConstraint==========")
	ancestries, ancestriesFound, ancestriesErr := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "ancestries")
	targets, targetsFound, targetsErr := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "target")
	if ancestriesFound && targetsFound {
		return errors.New("only one of spec.match.ancestries and spec.match.target can be specified")
	} else if ancestriesFound {
		if ancestriesErr != nil {
			return fmt.Errorf("invalid spec.match.ancestries: %s", ancestriesErr)
		}
		if ancestriesErr := checkPathGlobs(ancestries); ancestriesErr != nil {
			return fmt.Errorf("invalid glob in spec.match.ancestries: %w", ancestriesErr)
		}
	} else if targetsFound {
		// TODO b/232980918: replace with zapLogger.Warn
		log.Print(
			"spec.match.target is deprecated and will be removed in a future release. Use spec.match.ancestries instead",
		)
		if targetsErr != nil {
			return fmt.Errorf("invalid spec.match.target: %s", targetsErr)
		}
		if targetsErr := checkPathGlobs(targets); targetsErr != nil {
			return fmt.Errorf("invalid glob in spec.match.target: %w", targetsErr)
		}
	}

	excludedAncestries, excludedAncestriesFound, excludedAncestriesErr := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "excludedAncestries")
	excludes, excludesFound, excludesErr := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "exclude")
	if excludedAncestriesFound && excludesFound {
		return errors.New("only one of spec.match.excludedAncestries and spec.match.exclude can be specified")
	} else if excludedAncestriesFound {
		if excludedAncestriesErr != nil {
			return fmt.Errorf("invalid spec.match.excludedAncestries: %s", excludedAncestriesErr)
		}
		if excludedAncestriesErr := checkPathGlobs(excludedAncestries); excludedAncestriesErr != nil {
			return fmt.Errorf("invalid glob in spec.match.excludedAncestries: %w", excludedAncestriesErr)
		}
	} else if excludesFound {
		// TODO b/232980918: replace with zapLogger.Warn
		log.Print(
			"spec.match.exclude is deprecated and will be removed in a future release. Use spec.match.excludedAncestries instead",
		)
		if excludesErr != nil {
			return fmt.Errorf("invalid spec.match.exclude: %s", excludesErr)
		}
		if excludesErr := checkPathGlobs(excludes); excludesErr != nil {
			return fmt.Errorf("invalid glob in spec.match.exclude: %w", excludesErr)
		}
	}
	return nil
}

// Empty main.go to allow for installing root package.
func main() {
	fmt.Println("Initializing Client")
	driver := local.New(local.Tracing(true))
	backend, err := cfclient.NewBackend(cfclient.Driver(driver))
	if err != nil {
		// fmt.Println("Error: Could not initialize backend: %s", err)
		return
	}
	cfClient, err := backend.NewClient(cfclient.Targets(New()))
	if err != nil {
		// fmt.Println("Error: unable to set up OPA client: %s", err)
		return
	}

	ctx := context.Background()

	constraintTemplate := newConstraintTemplate(defaultTargetName, defaultConstraintTemplateRego)

	resp, err := cfClient.AddTemplate(ctx, constraintTemplate)

	// Create synthetic constraint
	constraintSpec := map[string]interface{}{
		"parameters": map[string]interface{}{
			"kind": "VirtualMachine",
			"type": "Microsoft.Compute/virtualMachines",
			"msg":  "No VMs allowed",
		},
	}
	
	constraint := map[string]interface{}{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1",
		"kind":       testConstraintKind,
		"metadata": map[string]interface{}{
			"name": strings.ToLower(testConstraintKind),
		},
		"spec": constraintSpec,
	}

	resp, err = cfClient.AddConstraint(ctx, &unstructured.Unstructured{Object: constraint})
	fmt.Println(resp)

	data := `
{
	"name": "test-name",
	"asset_type": "test-asset-type",
	"ancestry_path": "organizations/123454321/folders/1221214/projects/557385378",
	"resource": {}
}`
	var item interface{}
	json.Unmarshal([]byte(data), &item)
	fmt.Println(item)

	result, err := cfClient.Review(ctx, item, cfclient.Tracing(true))

	fmt.Println(result)
	fmt.Println(result.ByTarget["arm.policy.azure.com"].Trace)
	fmt.Println(result.ByTarget["arm.policy.azure.com"].Target)
	fmt.Println(result.ByTarget["arm.policy.azure.com"].Results)
	fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0])
	fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].Msg)
	fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].Metadata)
	fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].Constraint)
	fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].EnforcementAction)
}
