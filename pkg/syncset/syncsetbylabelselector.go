// Package syncset provides a type to map LabelSelectors to arbitrary objects
// and render the minimal set of SelectorSyncSets based on the LabelSelectors.
// The idea is to use it as a replacement for map[metav1.LabelSelector]runtime.RawExtension.
// A map cannot be used because metav1.LabelSelector cannot be used as a key in a map.
// This implementation uses reflect.DeepEqual to compare map keys.
package syncset

import (
	"encoding/json"
	"fmt"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	"os"
	"reflect"

	hivev1 "github.com/openshift/hive/apis/hive/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// SyncSetResourcesByLabelSelector is a mapping data structure.
// It uses metav1.LabelSelector as key and runtime.RawExtension as value.
// The builtin map type cannot be used because metav1.LabelSelector cannot be used as key.
type SyncSetResourcesByLabelSelector struct {
	entries []mapEntry
}

type mapEntry struct {
	key    metav1.LabelSelector
	values []runtime.RawExtension
}

// Add adds a resources to a SyncSetResourcesByLabelSelector object
func (s *SyncSetResourcesByLabelSelector) Add(key metav1.LabelSelector, object runtime.RawExtension) {
	existingEntry := s.Get(key)

	if existingEntry != nil {
		existingEntry.values = append(existingEntry.values, object)
		return
	}

	s.entries = append(s.entries, mapEntry{key, []runtime.RawExtension{object}})
}

// Get returns a single entry based on the passed key. If none exists, it returns nil
func (s *SyncSetResourcesByLabelSelector) Get(key metav1.LabelSelector) *mapEntry {
	for i, entry := range s.entries {
		if reflect.DeepEqual(entry.key, key) {
			return &s.entries[i]
		}
	}
	return nil
}

// RenderSelectorSyncSets renders a minimal set of SelectorSyncSets based on the LabelSelectors
// existing in the SyncSetResourcesByLabelSelector object
func (s *SyncSetResourcesByLabelSelector) RenderSelectorSyncSets(labels map[string]string) []runtime.RawExtension {
	sss := []runtime.RawExtension{}
	for i, entry := range s.entries {
		sss = append(sss, runtime.RawExtension{
			Raw: Encode(createSelectorSyncSet(
				fmt.Sprintf("managed-cluster-validating-webhooks-%d", i),
				entry.values,
				entry.key,
				labels,
			),
			),
		})
	}
	return sss
}

func createSelectorSyncSet(name string, resources []runtime.RawExtension, selector metav1.LabelSelector, labels map[string]string) *hivev1.SelectorSyncSet {
	return &hivev1.SelectorSyncSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SelectorSyncSet",
			APIVersion: "hive.openshift.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: hivev1.SelectorSyncSetSpec{
			SyncSetCommonSpec: hivev1.SyncSetCommonSpec{
				ResourceApplyMode: hivev1.SyncResourceApplyMode,
				Resources:         resources,
			},
			ClusterDeploymentSelector: selector,
		},
	}
}

func Encode(obj interface{}) []byte {
	o, err := json.Marshal(obj)
	if err != nil {
		fmt.Printf("Error encoding %+v\n", obj)
		os.Exit(1)
	}
	return o
}

func EncodeAndFixCA(vw admissionregv1.ValidatingWebhookConfiguration) ([]byte, error) {

	// Get the existing caBundle value
	if len(vw.Webhooks) < 1 {
		return nil, fmt.Errorf("Require at least one webhook")
	}
	caBundleValue := string(vw.Webhooks[0].ClientConfig.CABundle)

	// Convert to json
	o, err := json.Marshal(vw)
	if caBundleValue == "" {
		return o, err
	}

	// fix broken CABundle setting here
	var decoded interface{}
	json.Unmarshal(o, &decoded)

	// set the CA
	decoded.(map[string]interface{})["webhooks"].([]interface{})[0].(map[string]interface{})["clientConfig"].(map[string]interface{})["caBundle"] = caBundleValue

	// convert back to json
	r, err := json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("Error encoding %+v\n", decoded)
	}
	return r, nil
}
