package config

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	yaml "github.com/ghodss/yaml"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
)

// ManagedNamespacesConfig defines the structure of the managed_namespaces.yaml file from the managed-namespaces ConfigMap
type ManagedNamespacesConfig struct {
	Resources ManagedNamespaceList `yaml:"Resources,omitempty" json:"Resources,omitempty"`
}

type ManagedNamespaceList struct {
	Namespace []ManagedNamespace `yaml:"Namespace,omitempty" json:"Namespace,omitempty"`
}

type ManagedNamespace struct {
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
}

const (
	managedNamespaceConfigKey string = "managed_namespaces.yaml"
	defaultNamespaceRegex     string = "openshift.*"
	serviceAccountHeader      string = `^system:serviceaccounts:`

	// Exported constants
	ManagedNamespaceConfigName string = "managed-namespaces"
	ManagedNamespaceConfigNS   string = "openshift-monitoring"
)

var (
	log = logf.Log.WithName("config")

	// Exported variables
	PrivilegedNamespaces      = []string{"^kube$", "^kube-.*", "^default$", "^redhat.*"}
	PrivilegedServiceAccounts = []string{serviceAccountHeader + "kube.*", serviceAccountHeader + "default", serviceAccountHeader + "redhat.*", serviceAccountHeader + "osde2e-[a-z0-9]{5}"}
)

func IsPrivilegedNamespace(ns string) bool {
	return utils.RegexSliceContains(ns, PrivilegedNamespaces)
}

func IsPrivilegedServiceAccount(sa string) bool {
	return utils.RegexSliceContains(sa, PrivilegedServiceAccounts)
}

// Returns list of namespaces from 'managed-namespaces' ConfigMap.
// Defaults to returning 'openshift.*' regex on error
func GetManagedNamespaces() {
	defaultPrivilegedNamespaces := append(PrivilegedNamespaces, defaultNamespaceRegex)
	cfg, err := config.GetConfig()
	if err != nil {
		log.Error(err, fmt.Sprintf("Error retrieving cluster kubeconfig."))
		PrivilegedNamespaces = defaultPrivilegedNamespaces
		return
	}

	c, err := client.New(cfg, client.Options{})
	if err != nil {
		log.Error(err, fmt.Sprintf("Error creating client to retrieve managed-namespaces. Defaulting to regex %s", defaultNamespaceRegex))
		PrivilegedNamespaces = defaultPrivilegedNamespaces
		return
	}

	configMap := &corev1.ConfigMap{}
	err = c.Get(context.TODO(), client.ObjectKey{
		Namespace: ManagedNamespaceConfigNS,
		Name:      ManagedNamespaceConfigName,
	}, configMap)
	if err != nil {
		log.Error(err, "Error retrieving configMap", "configMap", ManagedNamespaceConfigName, "namespace", ManagedNamespaceConfigNS, "Defaulting to regex ", fmt.Sprintf("%s", defaultNamespaceRegex))
		PrivilegedNamespaces = defaultPrivilegedNamespaces
		return
	}

	var managedNamespaces ManagedNamespacesConfig
	rawManagedNamespaces := configMap.Data[managedNamespaceConfigKey]
	err = yaml.Unmarshal([]byte(rawManagedNamespaces), &managedNamespaces)
	if (err != nil) || (len(managedNamespaces.Resources.Namespace) < 1) {
		log.Error(err, "Error unmarshalling managed-namespace ConfigMap or no namespaces provided in config.")
		PrivilegedNamespaces = defaultPrivilegedNamespaces
		return
	}

	for _, namespace := range managedNamespaces.Resources.Namespace {
		AddNamespace(namespace.Name)
	}
}

func AddNamespace(ns string) {
	PrivilegedNamespaces = append(PrivilegedNamespaces, "^"+ns+"$")
	PrivilegedServiceAccounts = append(PrivilegedServiceAccounts, serviceAccountHeader+ns+"$")
}
