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
	return libraryTemplate
}

// ProcessData implements client.TargetHandler
func (g *ARMTarget) ProcessData(obj interface{}) (bool, string, interface{}, error) {
	return false, "", nil, errors.New("Storing data for referential constraint eval is not supported at this time.")
}

// HandleReview implements client.TargetHandler
func (g *ARMTarget) HandleReview(obj interface{}) (bool, interface{}, error) {
	switch asset := obj.(type) {
	case map[string]interface{}:
		return true, asset, nil
	}
	return false, nil, nil
}

// HandleViolation implements client.TargetHandler
func (g *ARMTarget) HandleViolation(result *types.Result) error {
	result.Resource = result.Review
	return nil
}

// ValidateConstraint implements client.TargetHandler
func (g *ARMTarget) ValidateConstraint(constraint *unstructured.Unstructured) error {
	return nil
}

// Basic constraint template.
// Denys if the kind and type of resouce are same in parameters and revies
const defaultConstraintTemplateRego = `
package constraint

violation[{"msg": msg, "details": input}] {
	input.review.kind == input.parameters.kind
	input.review.type == input.parameters.type
	msg := input.parameters.msg
}
`

func newConstraintTemplate(targetName, rego string) *cftemplates.ConstraintTemplate {
	// Building a correct constraint template is difficult based on the struct. It's easier
	// to reason about yaml files and rely on existing conversion code.
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

	groupVersioner := runtime.GroupVersioner(schema.GroupVersions(scheme.Scheme.PrioritizedVersionsAllGroups()))
	obj, err := scheme.Scheme.ConvertToVersion(&unstructured.Unstructured{Object: ctRaw}, groupVersioner)
	if err != nil {
		panic(err)
	}

	var ct cftemplates.ConstraintTemplate

	if err := scheme.Scheme.Convert(obj, &ct, nil); err != nil {
		panic(err)
	}

	return &ct
}

func main() {
	// Add constraint framework schemas
	utilruntime.Must(cfapis.AddToScheme(scheme.Scheme))
	utilruntime.Must(apiextensions.AddToScheme(scheme.Scheme))
	utilruntime.Must(apiextensionsv1beta1.AddToScheme(scheme.Scheme))

	// Instantiate driver using constraint framework
	driver := local.New(local.Tracing(true))

	// Instantiate backend using constraint framework and driver
	backend, err := cfclient.NewBackend(cfclient.Driver(driver))
	if err != nil {
		fmt.Println("Error: Could not initialize backend: ", err)
		return
	}

	// Instantiate Constraint Framework Client with ARMTarget
	cfClient, err := backend.NewClient(cfclient.Targets(New()))
	if err != nil {
		fmt.Println("Error: unable to set up OPA client: ", err)
		return
	}

	// Get background context
	ctx := context.Background()

	// Create new constraint template
	constraintTemplate := newConstraintTemplate(defaultTargetName, defaultConstraintTemplateRego)

	// Add template to the client
	cfClient.AddTemplate(ctx, constraintTemplate)

	// Create synthetic constraint
	// This sets the parameters used in the constraint framework
	constraintSpec := map[string]interface{}{
		"parameters": map[string]interface{}{
			"kind": "VirtualMachine",
			"type": "Microsoft.Compute/virtualMachines",
			"msg":  "No VMs allowed",
		},
	}
	
	// Create constraint object
	constraint := map[string]interface{}{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1",
		"kind":       testConstraintKind,
		"metadata": map[string]interface{}{
			"name": strings.ToLower(testConstraintKind),
		},
		"spec": constraintSpec,
	}

	// Add constraint to the client
	cfClient.AddConstraint(ctx, &unstructured.Unstructured{Object: constraint})

	// Actual data to be passed in to the constraint framework
	data := `
{
	"kind": "VirtualMachine",
	"type": "Microsoft.Compute/virtualMachines",
	"resource": {}
}`

	// Create review item
	var item interface{}
	json.Unmarshal([]byte(data), &item)

	result, err := cfClient.Review(ctx, item, cfclient.Tracing(true))

	fmt.Println("========== RESULTS ==========")
	if len(result.ByTarget["arm.policy.azure.com"].Results) != 0 {
		fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].Msg)
		fmt.Println(result.ByTarget["arm.policy.azure.com"].Results[0].EnforcementAction)
	} else {
		fmt.Println("========== NO VIOLATIONS ==========")
	}

	nonVMData := `
{
	"kind": "NotAVirtualMachine",
	"type": "Microsoft.Compute/notAVirtualMachines",
	"resource": {}
}`

	// Create review item
	var nonVMItem interface{}
	json.Unmarshal([]byte(nonVMData), &nonVMItem)

	nonVMResult, err := cfClient.Review(ctx, nonVMItem, cfclient.Tracing(true))
	fmt.Println("========== RESULTS ==========")
	if len(nonVMResult.ByTarget["arm.policy.azure.com"].Results) != 0 {
		fmt.Println(nonVMResult.ByTarget["arm.policy.azure.com"].Results[0].Msg)
		fmt.Println(nonVMResult.ByTarget["arm.policy.azure.com"].Results[0].EnforcementAction)
	} else {
		fmt.Println("========== NO VIOLATIONS ==========")
	}

	cfClient.RemoveConstraint(ctx, &unstructured.Unstructured{Object: constraint})

	newResult, err := cfClient.Review(ctx, item, cfclient.Tracing(true))
	fmt.Println("========== RESULTS ==========")
	if len(newResult.ByTarget["arm.policy.azure.com"].Results) != 0 {
		fmt.Println(newResult.ByTarget["arm.policy.azure.com"].Results[0].Msg)
		fmt.Println(newResult.ByTarget["arm.policy.azure.com"].Results[0].EnforcementAction)
	} else {
		fmt.Println("========== NO VIOLATIONS ==========")
	}
}
