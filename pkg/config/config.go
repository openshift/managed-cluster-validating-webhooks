package config

//go:generate go run ./generate/namespaces.go
import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
)

func IsPrivilegedNamespace(ns string) bool {
	return utils.RegexSliceContains(ns, PrivilegedNamespaces)
}

func IsPrivilegedServiceAccount(sa string) bool {
	return utils.RegexSliceContains(sa, PrivilegedServiceAccounts)
}
