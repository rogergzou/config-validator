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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	// Constraint Framework Client
	cfapis "github.com/open-policy-agent/frameworks/constraint/pkg/apis"
	cfclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	cftemplates "github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubectl/pkg/scheme"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

const defaultTargetName = "arm.policy.azure.com"

const testVersion = "v1beta1"
const testConstraintKind = "ArmPolicyConstraint"

func newConstraintTemplate(targetName, rego string) *cftemplates.ConstraintTemplate {
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
	ctRaw := map[string]interface{}{
		"apiVersion": fmt.Sprintf("templates.gatekeeper.sh/%s", testVersion),
		"kind":       "ConstraintTemplate",
		"metadata": map[string]interface{}{
			"name": strings.ToLower(testConstraintKind),
		},
		"spec": ctSpec,
	}

	fmt.Println("========== CT ==========")
	fmt.Println(ctRaw)

	groupVersioner := runtime.GroupVersioner(schema.GroupVersions(scheme.Scheme.PrioritizedVersionsAllGroups()))
	obj, err := scheme.Scheme.ConvertToVersion(&unstructured.Unstructured{Object: ctRaw}, groupVersioner)
	fmt.Println("======= VERSION OBJ")
	fmt.Println(obj)
	if err != nil {
		panic(err)
	}

	var ct cftemplates.ConstraintTemplate

	fmt.Println("======= CT OBJ")
	fmt.Println(ct)
	if err := scheme.Scheme.Convert(obj, &ct, nil); err != nil {
		panic(err)
	}

	return &ct
}

// ARM LIBRARY TEMPLATE IMPLEMENTATION
/*
This comment puts the start of rego on line 10 so it's easier to do math when
it calls out the line number.
*/
const libraryTemplateSrc = `package target

matching_constraints[constraint] {
	constraint := {{.ConstraintsRoot}}[_][_]
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
	fmt.Println("==========ARM MatchSchema==========")
	schema := apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
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
		return true, asset, nil
	}
	return false, nil, nil
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
	fmt.Println(constraint)
	return nil
}

const defaultConstraintTemplateRego = `
package constraint

violation[{"msg": msg, "details": input}] {
	input.review.kind == input.parameters.kind
	input.review.type == input.parameters.type
	msg := input.parameters.msg
}
`

// Empty main.go to allow for installing root package.
func main() {
	fmt.Println("Initializing Client")

	utilruntime.Must(cfapis.AddToScheme(scheme.Scheme))
	utilruntime.Must(apiextensions.AddToScheme(scheme.Scheme))
	utilruntime.Must(apiextensionsv1beta1.AddToScheme(scheme.Scheme))

	driver := local.New(local.Tracing(true))
	backend, err := cfclient.NewBackend(cfclient.Driver(driver))
	if err != nil {
		fmt.Println("Error: Could not initialize backend: ", err)
		return
	}
	cfClient, err := backend.NewClient(cfclient.Targets(New()))
	if err != nil {
		fmt.Println("Error: unable to set up OPA client: ", err)
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
	"kind": "VirtualMachine",
	"type": "Microsoft.Compute/virtualMachines",
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
	if len(result.ByTarget["arm.policy.azure.com"].Results) != 0 {
		fmt.Println("========== RESULTS ==========")
		fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0])
		fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].Msg)
		fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].Metadata)
		fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].Constraint)
		fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].EnforcementAction)
	}
}
