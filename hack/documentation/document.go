package main

// Offer a way to auto-generate documentation

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	hideRules = flag.Bool("hideRules", false, "Hide the Admission Rules?")
)

type docuhook struct {
	Name                string                              `json:"webhookName"`
	Rules               []admissionregv1.RuleWithOperations `json:"rules,omitempty"`
	ObjectSelector      *metav1.LabelSelector               `json:"webhookObjectSelector,omitempty"`
	DocumentationString string                              `json:"documentString"`
}

// WriteDocs will write out all the docs.
func WriteDocs() {
	hookNames := make([]string, 0)
	for name := range webhooks.Webhooks {
		hookNames = append(hookNames, name)
	}
	sort.Strings(hookNames)
	dochooks := make([]docuhook, len(hookNames))

	for i, hookName := range hookNames {
		hook := webhooks.Webhooks[hookName]
		realHook := hook()
		dochooks[i].Name = realHook.Name()
		dochooks[i].DocumentationString = realHook.Doc()
		if !*hideRules {
			dochooks[i].Rules = realHook.Rules()
			dochooks[i].ObjectSelector = realHook.ObjectSelector()
		}
	}

	b, err := json.MarshalIndent(&dochooks, "", "  ")
	if err != nil {
		fmt.Printf("Error encoding: %s\n", err.Error())
		os.Exit(1)
	}
	_, err = os.Stdout.Write(b)
	if err != nil {
		fmt.Printf("Error Writing: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Println()

}

func main() {
	flag.Parse()
	WriteDocs()
}
