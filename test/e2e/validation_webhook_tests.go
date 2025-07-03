//go:build osde2e
// +build osde2e

package osde2etests

import (
	"context"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	quotav1 "github.com/openshift/api/quota/v1"
	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/osde2e-common/pkg/clients/openshift"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

var _ = Describe("Managed Cluster Validating Webhooks", Ordered, func() {
	var (
		client             *openshift.Client
		dedicatedAdmink8s  *openshift.Client
		userk8s            *openshift.Client
		clusterAdmink8s    *openshift.Client
		unauthenticatedk8s *openshift.Client
		dynamicClient      dynamic.Interface
		testNamespace      *v1.Namespace
	)
	const (
		namespaceName         = "openshift-validation-webhook"
		serviceName           = "validation-webhook"
		daemonsetName         = "validation-webhook"
		configMapName         = "webhook-cert"
		secretName            = "webhook-cert"
		testNsName            = "osde2e-temp-ns"
		privilegedNamespace   = "openshift-backplane"
		unprivilegedNamespace = "openshift-logging"
	)

	createNS := func(ns string) {
		testNamespace = &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
		err := client.Create(context.TODO(), testNamespace)
		By("checking the custom namespace exists")
		err = wait.For(conditions.New(client.Resources).ResourceMatch(testNamespace, func(object k8s.Object) bool {
			return true
		}))
		Expect(err).ShouldNot(HaveOccurred(), "Unable to create test namespace")
	}

	deleteNS := func(ns *v1.Namespace) {
		err := client.Delete(context.TODO(), ns)
		err = wait.For(conditions.New(client.Resources).ResourceDeleted(ns))
		Expect(err).ShouldNot(HaveOccurred(), "Unable to delete test namespace")
	}

	BeforeAll(func() {
		log.SetLogger(GinkgoLogr)
		var err error
		client, err = openshift.New(GinkgoLogr)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup k8s client")
		cfg, err := config.GetConfig()
		Expect(err).Should(BeNil(), "Unable to get kubeconfig")

		dedicatedAdmink8s, err = client.Impersonate("test-user@redhat.com", "dedicated-admins")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated dedicated admin client")
		clusterAdmink8s, err = client.Impersonate("system:admin", "cluster-admins")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated cluster admin client")
		userk8s, err = client.Impersonate("majora", "system:authenticated")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated user client")
		unauthenticatedk8s, err = client.Impersonate("system:unauthenticated")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated unauthenticated user client")
		dynamicClient, err = dynamic.NewForConfig(cfg)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to create dynamic client")
	})

	It("exists and is running", func(ctx context.Context) {
		By("checking the namespace exists")
		err := client.Get(ctx, namespaceName, namespaceName, &v1.Namespace{})
		Expect(err).ToNot(HaveOccurred())

		By("checking the configmaps exist")
		err = client.Get(ctx, configMapName, namespaceName, &v1.ConfigMap{})
		Expect(err).ToNot(HaveOccurred())

		By("checking the secret exists")
		err = client.Get(ctx, secretName, namespaceName, &v1.Secret{})
		Expect(err).ToNot(HaveOccurred())

		By("checking the service exists")
		err = client.Get(ctx, serviceName, namespaceName, &v1.Service{})
		Expect(err).ToNot(HaveOccurred())

		By("checking the daemonset exists")
		ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: daemonsetName, Namespace: namespaceName}}
		err = wait.For(conditions.New(client.Resources).ResourceMatch(ds, func(object k8s.Object) bool {
			d := object.(*appsv1.DaemonSet)
			desiredNumScheduled := d.Status.DesiredNumberScheduled
			return d.Status.CurrentNumberScheduled == desiredNumScheduled &&
				d.Status.NumberReady == desiredNumScheduled &&
				d.Status.NumberAvailable == desiredNumScheduled
		}))
		Expect(err).ToNot(HaveOccurred())
	})

	It("should create a pod with the correct security context", func(ctx context.Context) {
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testpod",
				Namespace: namespaceName,
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{
						Name:  "test",
						Image: "quay.io/jitesoft/nginx:mainline",
						SecurityContext: &v1.SecurityContext{
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &v1.Capabilities{
								Drop: []v1.Capability{"ALL"},
							},
							RunAsNonRoot: pointer.BoolPtr(true),
							SeccompProfile: &v1.SeccompProfile{
								Type: v1.SeccompProfileTypeRuntimeDefault,
							},
						},
					},
				},
			},
		}

		err := client.Create(ctx, pod)
		Expect(err).NotTo(HaveOccurred())
		err = client.Delete(ctx, pod)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("sre-pod-validation", Ordered, func() {
		const (
			deletePodWaitDuration = 5 * time.Minute
			createPodWaitDuration = 1 * time.Minute
		)

		var pod *v1.Pod

		BeforeAll(func() {
			pod = &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      envconf.RandomName("testpod", 12),
					Namespace: privilegedNamespace,
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "test-ubi",
							Image: "registry.access.redhat.com/ubi8/ubi-minimal",
							SecurityContext: &v1.SecurityContext{
								AllowPrivilegeEscalation: pointer.BoolPtr(false),
								Capabilities: &v1.Capabilities{
									Drop: []v1.Capability{"ALL"},
								},
								RunAsNonRoot: pointer.BoolPtr(true),
								SeccompProfile: &v1.SeccompProfile{
									Type: v1.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
						{
							Name:  "test-nginx",
							Image: "quay.io/jitesoft/nginx:mainline",
							SecurityContext: &v1.SecurityContext{
								AllowPrivilegeEscalation: pointer.BoolPtr(false),
								Capabilities: &v1.Capabilities{
									Drop: []v1.Capability{"ALL"},
								},
								RunAsNonRoot: pointer.BoolPtr(true),
								SeccompProfile: &v1.SeccompProfile{
									Type: v1.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
					Tolerations: []v1.Toleration{
						{
							Key:    "node-role.kubernetes.io/master",
							Value:  "toleration-key-value",
							Effect: v1.TaintEffectNoSchedule,
						},
						{
							Key:    "node-role.kubernetes.io/infra",
							Value:  "toleration-key-value2",
							Effect: v1.TaintEffectNoSchedule,
						},
					},
				},
			}
		})

		It("blocks pods scheduled onto master/infra nodes", func(ctx context.Context) {
			err := dedicatedAdmink8s.Create(ctx, pod)
			Expect(errors.IsForbidden(err)).To(BeTrue())

			err = userk8s.Create(ctx, pod)
			Expect(errors.IsForbidden(err)).To(BeTrue())

			pod.SetNamespace(unprivilegedNamespace)
			err = userk8s.Create(ctx, pod)
			Expect(errors.IsForbidden(err)).To(BeTrue())
			pod.SetNamespace(privilegedNamespace)
		}, SpecTimeout(createPodWaitDuration.Seconds()+deletePodWaitDuration.Seconds()))

		It("allows cluster-admin to schedule pods onto master/infra nodes", func(ctx context.Context) {
			sa := &v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "webhook-sa",
					Namespace: namespaceName,
				},
			}
			err := client.Create(ctx, sa)
			Expect(err).ShouldNot(HaveOccurred(), "Unable to create service account")
			err = client.Delete(ctx, sa)
			Expect(err).ShouldNot(HaveOccurred(), "Unable to delete service account")

			err = client.Create(ctx, pod)
			Expect(err).NotTo(HaveOccurred())
			err = client.Delete(ctx, pod)
			Expect(err).NotTo(HaveOccurred())
		}, SpecTimeout(createPodWaitDuration.Seconds()+deletePodWaitDuration.Seconds()))

	})

	Describe("sre-techpreviewnoupgrade-validation", func() {
		It("blocks customers from setting TechPreviewNoUpgrade feature gate", func(ctx context.Context) {
			clusterFeatureGate := &configv1.FeatureGate{}
			err := clusterAdmink8s.Get(ctx, "cluster", "", clusterFeatureGate)
			Expect(err).NotTo(HaveOccurred())

			clusterFeatureGate.Spec.FeatureSet = "TechPreviewNoUpgrade"
			err = clusterAdmink8s.Update(ctx, clusterFeatureGate)
			Expect(errors.IsForbidden(err)).To(BeTrue())
		})
	})

	Describe("sre-regular-user-validation", func() {
		It("blocks unauthenticated users from managing \"managed\" resources", func(ctx context.Context) {
			cvo := &configv1.ClusterVersion{ObjectMeta: metav1.ObjectMeta{Name: "osde2e-version"}}
			err := unauthenticatedk8s.Create(ctx, cvo)
			Expect(errors.IsForbidden(err)).To(BeTrue())
		})

		DescribeTable(
			"allows privileged users to manage \"managed\" resources",
			func(ctx context.Context, user string) {
				userk8s, err := client.Impersonate(user)
				cvo := &configv1.ClusterVersion{ObjectMeta: metav1.ObjectMeta{Name: "osde2e-version"}}
				err = userk8s.Create(ctx, cvo)
				Expect(err).NotTo(HaveOccurred())
				err = userk8s.Delete(ctx, cvo)
				Expect(err).NotTo(HaveOccurred())
			},
			Entry("as system:admin", "system:admin"),
			Entry("as backplane-cluster-admin", "backplane-cluster-admin"),
		)

		BeforeAll(func(ctx context.Context) {
			createNS(testNsName)
		})

		AfterAll(func(ctx context.Context) {
			deleteNS(testNamespace)
		})

		It("only blocks configmap/user-ca-bundle changes", func(ctx context.Context) {
			cm := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "user-ca-bundle", Namespace: "openshift-config"}}
			err := dedicatedAdmink8s.Delete(ctx, cm)
			Expect(errors.IsForbidden(err)).To(BeTrue(), "Expected to be forbidden from deleting user-ca-bundle ConfigMap")

			cm = &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testNsName},
				Data:       map[string]string{"test": "test"},
			}
			err = dedicatedAdmink8s.Create(ctx, cm)
			Expect(err).NotTo(HaveOccurred(), "Expected to create ConfigMap in test namespace")
			err = dedicatedAdmink8s.Delete(ctx, cm)
			Expect(err).NotTo(HaveOccurred(), "Expected to delete ConfigMap in test namespace")
		})

		It("blocks modifications to nodes", func(ctx context.Context) {
			var nodes v1.NodeList
			selectInfraNodes := resources.WithLabelSelector(labels.FormatLabels(map[string]string{"node-role.kubernetes.io": "infra"}))
			err := dedicatedAdmink8s.List(ctx, &nodes, selectInfraNodes)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(nodes.Items)).Should(BeNumerically(">", 0), "failed to find infra nodes")

			node := nodes.Items[0]
			node.SetLabels(map[string]string{"osde2e": ""})
			err = dedicatedAdmink8s.Update(ctx, &node)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("forbidden"))
		})

		// TODO: test "system:serviceaccounts:openshift-backplane-cee" group can use NetNamespace CR

		It("allows dedicated-admin to manage CustomDomain CRs", func(ctx context.Context) {
			dynamicClient, err := dynamic.NewForConfig(dedicatedAdmink8s.GetConfig())
			Expect(err).ShouldNot(HaveOccurred(), "failed creating the dynamic client: %w", err)

			cdc := dynamicClient.Resource(schema.GroupVersionResource{
				Group:    "managed.openshift.io",
				Version:  "v1alpha1",
				Resource: "customdomains",
			})

			newCustomDomainObject := new(unstructured.Unstructured)
			newCustomDomainObject.SetUnstructuredContent(map[string]interface{}{
				"apiVersion": "managed.openshift.io/v1alpha1",
				"kind":       "CustomDomain",
				"metadata": map[string]string{
					"name": "test-cd",
				},
			})

			_, err = cdc.Create(ctx, newCustomDomainObject, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			err = cdc.Delete(ctx, "test-cd", metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("allows backplane-cluster-admin to manage MustGather CRs", func(ctx context.Context) {
			backplanecadmin, err := client.Impersonate("backplane-cluster-admin", "system:serviceaccounts:backplane-cluster-admin")
			Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated backplane-cluster-admin client")
			dynamicClient, err = dynamic.NewForConfig(backplanecadmin.GetConfig())
			Expect(err).ShouldNot(HaveOccurred(), "failed creating the dynamic client: %w", err)

			mgc := dynamicClient.Resource(schema.GroupVersionResource{
				Group:    "managed.openshift.io",
				Version:  "v1alpha1",
				Resource: "mustgathers",
			}).Namespace(namespaceName)

			newMustGatherObject := new(unstructured.Unstructured)
			newMustGatherObject.SetUnstructuredContent(map[string]interface{}{
				"apiVersion": "managed.openshift.io/v1alpha1",
				"kind":       "MustGather",
				"metadata": map[string]string{
					"name": "test-mg",
				},
			})

			_, err = mgc.Create(ctx, newMustGatherObject, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			err = mgc.Delete(ctx, "test-mg", metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("sre-hiveownership-validation", Ordered, func() {
		const quotaName = "-quota"
		var managedCRQ *quotav1.ClusterResourceQuota

		newTestCRQ := func(name string) *quotav1.ClusterResourceQuota {
			managed := strings.HasPrefix(name, "managed")
			return &quotav1.ClusterResourceQuota{
				ObjectMeta: metav1.ObjectMeta{
					Name:   name,
					Labels: map[string]string{"hive.openshift.io/managed": strconv.FormatBool(managed)},
				},
				Spec: quotav1.ClusterResourceQuotaSpec{
					Selector: quotav1.ClusterResourceQuotaSelector{
						AnnotationSelector: map[string]string{"openshift.io/requester": "test"},
					},
				},
			}
		}

		BeforeAll(func(ctx context.Context) {
			managedCRQ = newTestCRQ("managed" + quotaName)
			err := clusterAdmink8s.Create(ctx, managedCRQ)
			Expect(err).NotTo(HaveOccurred(), "Failed to create managed ClusterResourceQuota")
		})

		AfterAll(func(ctx context.Context) {
			err := clusterAdmink8s.Delete(ctx, managedCRQ)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete managed ClusterResourceQuota")
		})

		It("blocks deletion of managed ClusterResourceQuotas", func(ctx context.Context) {
			err := dedicatedAdmink8s.Delete(ctx, managedCRQ)
			Expect(errors.IsForbidden(err)).To(BeTrue(), "Expected deletion to be forbidden for dedicatedAdmink8s")
			err = userk8s.Delete(ctx, managedCRQ)
			Expect(errors.IsForbidden(err)).To(BeTrue(), "Expected deletion to be forbidden for client")
		})

		It("allows a member of SRE to update managed ClusterResourceQuotas", func(ctx context.Context) {
			userk8s, err := client.Impersonate("backplane-cluster-admin")
			managedCRQ.SetLabels(map[string]string{"osde2e": ""})
			err = userk8s.Update(ctx, managedCRQ)
			Expect(err).NotTo(HaveOccurred())
		})

		It("allows dedicated-admins can manage unmanaged ClusterResourceQuotas", func(ctx context.Context) {
			unmanagedCRQ := newTestCRQ("openshift" + quotaName)

			err := dedicatedAdmink8s.Create(ctx, unmanagedCRQ)
			Expect(err).NotTo(HaveOccurred())

			unmanagedCRQ.SetLabels(map[string]string{"osde2e": ""})
			err = dedicatedAdmink8s.Update(ctx, unmanagedCRQ)
			Expect(err).NotTo(HaveOccurred())

			err = dedicatedAdmink8s.Delete(ctx, unmanagedCRQ)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("sre-scc-validation", func() {
		It("blocks modifications to default SecurityContextConstraints", func(ctx context.Context) {
			scc := &securityv1.SecurityContextConstraints{ObjectMeta: metav1.ObjectMeta{Name: "privileged"}}
			scc.SetLabels(map[string]string{"osde2e": ""})

			err := dedicatedAdmink8s.Update(ctx, scc)
			Expect(errors.IsForbidden(err)).To(BeTrue())

			err = dedicatedAdmink8s.Delete(ctx, scc)
			Expect(errors.IsForbidden(err)).To(BeTrue())
		})
	})

	Describe("sre-namespace-validation", Ordered, func() {
		const testUser = "testuser@testdomain.com"
		const nonPrivilegedNamespace = "mykube-admin"

		// Map of namespace name and whether it should be created/deleted by the test
		// Should match up with namespaces found in managed-cluster-config:
		// * https://github.com/openshift/managed-cluster-config/blob/master/deploy/osd-managed-resources/ocp-namespaces.ConfigMap.yaml
		// * https://github.com/openshift/managed-cluster-config/blob/master/deploy/osd-managed-resources/managed-namespaces.ConfigMap.yaml
		privilegedNamespaces := map[string]bool{
			"default":                        false,
			"redhat-ocm-addon-test-operator": true,
		}
		privilegedUsers := []string{
			"system:admin",
			"backplane-cluster-admin",
		}

		createNamespace := func(ctx context.Context, name string) {
			err := clusterAdmink8s.Get(ctx, name, "", &v1.Namespace{})
			if errors.IsNotFound(err) {
				err = clusterAdmink8s.Create(ctx, &v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
						Labels: map[string]string{
							"pod-security.kubernetes.io/enforce":             "privileged",
							"pod-security.kubernetes.io/audit":               "privileged",
							"pod-security.kubernetes.io/warn":                "privileged",
							"security.openshift.io/scc.podSecurityLabelSync": "false",
						},
					},
				})
			}
			Expect(err).NotTo(HaveOccurred())
		}

		deleteNamespace := func(ctx context.Context, name string) {
			err := clusterAdmink8s.Delete(ctx, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
			Expect(err).NotTo(HaveOccurred())
		}

		updateNamespace := func(ctx context.Context, name, user string, groups ...string) error {
			userk8s, err := client.Impersonate(user, groups...)
			if err != nil {
				return err
			}

			ns := &v1.Namespace{}
			err = userk8s.Get(ctx, name, "", ns)
			if err != nil {
				return err
			}
			return userk8s.Update(ctx, ns)
		}

		BeforeAll(func(ctx context.Context) {
			for namespace, create := range privilegedNamespaces {
				if create {
					createNamespace(ctx, namespace)
				}
			}
			createNamespace(ctx, nonPrivilegedNamespace)
		})

		AfterAll(func(ctx context.Context) {
			for namespace, del := range privilegedNamespaces {
				if del {
					deleteNamespace(ctx, namespace)
				}
			}
			deleteNamespace(ctx, nonPrivilegedNamespace)
		})

		It("blocks dedicated admins from managing privileged namespaces", func(ctx context.Context) {
			for namespace := range privilegedNamespaces {
				err := updateNamespace(ctx, namespace, testUser, "dedicated-admins")
				Expect(errors.IsForbidden(err)).To(BeTrue())
			}
		})

		It("block non privileged users from managing privileged namespaces", func(ctx context.Context) {
			for namespace := range privilegedNamespaces {
				err := updateNamespace(ctx, namespace, testUser)
				Expect(errors.IsForbidden(err)).To(BeTrue())
			}
		})

		It("allows privileged users to manage all namespaces", func(ctx context.Context) {
			for _, user := range privilegedUsers {
				for namespace := range privilegedNamespaces {
					err := updateNamespace(ctx, namespace, user)
					Expect(err).NotTo(HaveOccurred())
				}
				err := updateNamespace(ctx, nonPrivilegedNamespace, user)
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("allows non privileged users to manage non privileged namespaces", func(ctx context.Context) {
			err := updateNamespace(ctx, nonPrivilegedNamespace, testUser, "dedicated-admins")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("sre-prometheusrule-validation", func() {
		newPrometheusRule := func(namespace string) *monitoringv1.PrometheusRule {
			return &monitoringv1.PrometheusRule{
				ObjectMeta: metav1.ObjectMeta{Name: "prometheus-example-app", Namespace: namespace},
				Spec: monitoringv1.PrometheusRuleSpec{
					Groups: []monitoringv1.RuleGroup{
						{
							Name: "example",
							Rules: []monitoringv1.Rule{
								{
									Alert: "VersionAlert",
									Expr:  intstr.FromString("version{job=\"prometheus-example-app\"} == 0"),
								},
							},
						},
					},
				},
			}
		}

		BeforeAll(func(ctx context.Context) {
			err := monitoringv1.AddToScheme(scheme.Scheme)
			Expect(err).NotTo(HaveOccurred(), "Failed to add PrometheusRule to scheme")
			rule := newPrometheusRule(privilegedNamespace)
			err = client.Delete(ctx, rule)
			Expect(err == nil || errors.IsNotFound(err)).To(BeTrue(), "Failed to ensure PrometheusRule deletion")
			createNS(testNsName)
		})

		AfterAll(func(ctx context.Context) {
			deleteNS(testNamespace)
		})

		DescribeTable(
			"blocks users from creating PrometheusRules in privileged namespaces",
			func(ctx context.Context, user string) {
				rule := newPrometheusRule(privilegedNamespace)
				userk8s, err := client.Impersonate(user, "system:authenticated")

				err = userk8s.Create(ctx, rule)
				Expect(err.Error()).To(ContainSubstring("forbidden"))
			},
			Entry("as dedicated-admin", "dedicated-admin"),
			Entry("as random user", "majora"),
		)

		It("allows backplane-cluster-admin to manage PrometheusRules in all namespaces", func(ctx context.Context) {
			backplanecadmin, err := client.Impersonate("backplane-cluster-admin")
			Expect(err).NotTo(HaveOccurred())

			rule := newPrometheusRule(privilegedNamespace)
			err = backplanecadmin.Create(ctx, rule)
			Expect(err).NotTo(HaveOccurred())
			err = backplanecadmin.Delete(ctx, rule)
			Expect(err).NotTo(HaveOccurred())

			rule = newPrometheusRule(namespaceName)
			err = backplanecadmin.Create(ctx, rule)
			Expect(err).NotTo(HaveOccurred())
			err = backplanecadmin.Delete(ctx, rule)
			Expect(err).NotTo(HaveOccurred())
		})

		It("allows non-privileged users to manage PrometheusRules in non-privileged namespaces", func(ctx context.Context) {
			rule := newPrometheusRule(testNsName)

			err := dedicatedAdmink8s.Create(ctx, rule)
			Expect(err).NotTo(HaveOccurred())

			err = dedicatedAdmink8s.Delete(ctx, rule)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
