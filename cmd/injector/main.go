package main

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/certinjector"
)

func main() {
	injector, err := certinjector.NewCertInjector()
	if err != nil {
		panic(err)
	}
	err = injector.Inject()
	if err != nil {
		panic(err)
	}
}
