module github.com/openshift/managed-cluster-validating-webhooks

go 1.14

require (
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32
	github.com/openshift/api v0.0.0-20210521075222-e273a339932a
	github.com/openshift/cluster-logging-operator v0.0.0-20210525135922-71decaca5680
	github.com/openshift/hive/apis v0.0.0-20210526051511-c6ca3dd7d0e4
	k8s.io/api v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/klog/v2 v2.9.0
	k8s.io/utils v0.0.0-20210521133846-da695404a2bc
	sigs.k8s.io/controller-runtime v0.8.3
)

replace (
	github.com/coreos/go-systemd => github.com/coreos/go-systemd/v22 v22.0.0 // Pin non-versioned import to v22.0.0
	github.com/metal3-io/baremetal-operator => github.com/openshift/baremetal-operator v0.0.0-20200206190020-71b826cc0f0a // Use OpenShift fork
	github.com/metal3-io/cluster-api-provider-baremetal => github.com/openshift/cluster-api-provider-baremetal v0.0.0-20190821174549-a2a477909c1d // Pin OpenShift fork
	github.com/terraform-providers/terraform-provider-azurerm => github.com/openshift/terraform-provider-azurerm v1.41.1-openshift-3 // Pin to openshift fork with IPv6 fixes
	go.etcd.io/etcd => go.etcd.io/etcd v0.0.0-20191023171146-3cf2f69b5738 // Pin to version used by k8s.io/apiserver
	k8s.io/client-go => k8s.io/client-go v0.21.1 // Pinned to keep from using an older v12.0.0 version that go mod thinks is newer
	sigs.k8s.io/cluster-api-provider-aws => github.com/openshift/cluster-api-provider-aws v0.2.1-0.20200316201703-923caeb1d0d8 // Pin OpenShift fork
	sigs.k8s.io/cluster-api-provider-azure => github.com/openshift/cluster-api-provider-azure v0.1.0-alpha.3.0.20200120114645-8a9592f1f87b // Pin OpenShift fork
	sigs.k8s.io/cluster-api-provider-openstack => github.com/openshift/cluster-api-provider-openstack v0.0.0-20200323110431-3311de91e078 // Pin OpenShift fork

)

replace bitbucket.org/ww/goautoneg => github.com/munnerz/goautoneg v0.0.0-20190414153302-2ae31c8b6b30
