//go:build osde2e
// +build osde2e

package osde2etests

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	quotav1 "github.com/openshift/api/quota/v1"
	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/osde2e-common/pkg/clients/openshift"
	"github.com/openshift/osde2e/pkg/common/expect"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/kubectl/pkg/util/slice"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

var _ = Describe("Managed Cluster Validating Webhooks", Ordered, func() {
	var (
		client            *openshift.Client
		dedicatedAdmink8s *openshift.Client
		userk8s           *openshift.Client
		clusterAdmink8s   *openshift.Client
		err               error
		resource          *resources.Resources
		// sak8s              *openshift.Client
		unauthenticatedk8s *openshift.Client
	)
	const (
		namespaceName = "openshift-validation-webhook"
		serviceName   = "validation-webhook"
		daemonsetName = "validation-webhook"
		configMapName = "webhook-cert"
		secretName    = "webhook-cert"
		saName        = "webhook-sa"
	)

	BeforeAll(func() {
		log.SetLogger(GinkgoLogr)
		var err error
		client, err = openshift.New(GinkgoLogr)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup k8s client")
		dedicatedAdmink8s, err = client.Impersonate("test-user@redhat.com", "dedicated-admins")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated dedicated admin client")
		clusterAdmink8s, err = client.Impersonate("system:admin", "cluster-admins")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated cluster admin client")
		userk8s, err = client.Impersonate("majora", "system:authenticated")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated user client")
		unauthenticatedk8s, err = client.Impersonate("", "system:unauthenticated")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated unauthenticated user client")
		// sak8s, err = client.Impersonate("test-user@redhat.com", "dedicated-admins")
		// Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated k8s client")
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
		err = wait.For(conditions.New(resource).ResourceMatch(ds, func(object k8s.Object) bool {
			d := object.(*appsv1.DaemonSet)
			desiredNumScheduled := d.Status.DesiredNumberScheduled
			return d.Status.CurrentNumberScheduled == desiredNumScheduled &&
				d.Status.NumberReady == desiredNumScheduled &&
				d.Status.NumberAvailable == desiredNumScheduled
		}))
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("sre-pod-validation", Ordered, func() {
		const (
			privilegedNamespace   = "openshift-backplane"
			unprivilegedNamespace = "openshift-logging"

			deletePodWaitDuration = 5 * time.Minute
			createPodWaitDuration = 1 * time.Minute
		)

		var pod *v1.Pod
		newTestPod := func(name string) *v1.Pod {
			return &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "test",
							Image: "registry.access.redhat.com/ubi8/ubi-minimal",
						},
					},
					Tolerations: []v1.Toleration{
						{
							Key:    "node-role.kubernetes.io/master",
							Value:  "toleration-key-value",
							Effect: v1.TaintEffectNoSchedule,
						}, {
							Key:    "node-role.kubernetes.io/infra",
							Value:  "toleration-key-value2",
							Effect: v1.TaintEffectNoSchedule,
						},
					},
				},
			}
		}

		withNamespace := func(pod *v1.Pod, namespace string) *v1.Pod {
			pod.SetNamespace(namespace)
			return pod
		}

		BeforeAll(func() {
			name := envconf.RandomName("testpod", 12)
			pod = newTestPod(name)
		})

		It("blocks pods scheduled onto master/infra nodes", func(ctx context.Context) {
			err := dedicatedAdmink8s.Create(ctx, withNamespace(pod, privilegedNamespace))
			Expect(apierrors.IsForbidden(err)).To(BeTrue())

			err = userk8s.Create(ctx, withNamespace(pod, privilegedNamespace))
			Expect(apierrors.IsForbidden(err)).To(BeTrue())

			err = client.Create(ctx, withNamespace(pod, unprivilegedNamespace))
			Expect(apierrors.IsForbidden(err)).To(BeTrue())
		}, SpecTimeout(createPodWaitDuration.Seconds()+deletePodWaitDuration.Seconds()))

		It("allows cluster-admin to schedule pods onto master/infra nodes", func(ctx context.Context) {
			// client := h.AsServiceAccount(fmt.Sprintf("system:serviceaccount:%s:dedicated-admin-project", h.CurrentProject()))
			err = client.Get(ctx, saName, namespaceName, &v1.ServiceAccount{})
			Expect(err).ShouldNot(HaveOccurred(), "Unable to setup service account")

			pod = withNamespace(pod, privilegedNamespace)
			err := client.Create(ctx, pod)
			Expect(err).NotTo(HaveOccurred())
			err = client.Delete(ctx, pod)
			Expect(err).NotTo(HaveOccurred())
		}, SpecTimeout(createPodWaitDuration.Seconds()+deletePodWaitDuration.Seconds()))

		It("prevents workloads from being scheduled on worker nodes", func(ctx context.Context) {
			operators := map[string]string{
				"cloud-ingress-operator":          "openshift-cloud-ingress-operator",
				"configure-alertmanager-operator": "openshift-monitoring",
				"custom-domains-operator":         "openshift-custom-domains-operator",
				"managed-upgrade-operator":        "openshift-managed-upgrade-operator",
				"managed-velero-operator":         "openshift-velero",
				"must-gather-operator":            "openshift-must-gather-operator",
				"osd-metrics-exporter":            "openshift-osd-metrics",
				"rbac-permissions-operator":       "openshift-rbac-permissions",
			}

			var podList v1.PodList
			err := client.List(ctx, &podList)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(podList.Items)).To(BeNumerically(">", 0), "found no pods")

			var nodeList v1.NodeList
			selectInfraNodes := resources.WithLabelSelector(labels.FormatLabels(map[string]string{"node-role.kubernetes.io": "infra"}))
			err = client.List(ctx, &nodeList, selectInfraNodes)
			Expect(err).NotTo(HaveOccurred())

			nodeNames := []string{}
			for _, node := range nodeList.Items {
				nodeNames = append(nodeNames, node.GetName())
			}

			violators := []string{}
			for _, pod := range podList.Items {
				for operator, namespace := range operators {
					if pod.GetNamespace() != namespace {
						continue
					}
					if strings.HasPrefix(pod.GetName(), operator) && !strings.HasPrefix(pod.GetName(), operator+"-registry") {
						if !slice.ContainsString(nodeNames, pod.Spec.NodeName, nil) {
							violators = append(violators, pod.GetNamespace()+"/"+pod.GetName())
						}
					}
				}
			}

			Expect(violators).To(HaveLen(0), "found pods in violation %v", violators)
		})
	})

	ginkgo.Describe("sre-techpreviewnoupgrade-validation", func() {
		ginkgo.It("blocks customers from setting TechPreviewNoUpgrade feature gate", func(ctx context.Context) {
			// clusterAdmink8s, err = client.Impersonate("system:admin", "cluster-admins")
			// Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated k8s client")
			clusterFeatureGate := &configv1.FeatureGate{}
			err := client.Get(ctx, "cluster", "", clusterFeatureGate)
			Expect(err).NotTo(HaveOccurred())

			clusterFeatureGate.Spec.FeatureSet = "TechPreviewNoUpgrade"
			err = client.Update(ctx, clusterFeatureGate)
			Expect(errors.IsForbidden(err)).To(BeTrue())
		})
	})

	ginkgo.Describe("sre-regular-user-validation", func() {
		ginkgo.It("blocks unauthenticated users from managing \"managed\" resources", func(ctx context.Context) {
			cvo := &configv1.ClusterVersion{ObjectMeta: metav1.ObjectMeta{Name: "osde2e-version"}}
			err := unauthenticatedk8s.Create(ctx, cvo)
			Expect(errors.IsForbidden(err)).To(BeTrue())
		})

		ginkgo.DescribeTable(
			"allows privileged users to manage \"managed\" resources",
			func(ctx context.Context, user string) {
				cvo := &configv1.ClusterVersion{ObjectMeta: metav1.ObjectMeta{Name: "osde2e-version"}}
				err := client.Create(ctx, cvo)
				Expect(err).NotTo(HaveOccurred())
				err = client.Delete(ctx, cvo)
				Expect(err).NotTo(HaveOccurred())
			},
			ginkgo.Entry("as system:admin", "system:admin"),
			ginkgo.Entry("as backplane-cluster-admin", "backplane-cluster-admin"),
		)

		ginkgo.It("only blocks configmap/user-ca-bundle changes", func(ctx context.Context) {
			cm := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "user-ca-bundle", Namespace: "openshift-config"}}
			err := client.Delete(ctx, cm)
			Expect(errors.IsForbidden(err)).To(BeTrue())

			cm = &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "test-namespace"},
				Data:       map[string]string{"test": "test"},
			}
			err = client.Create(ctx, cm)
			Expect(err).NotTo(HaveOccurred())
			err = client.Delete(ctx, cm)
			Expect(err).NotTo(HaveOccurred())
		})

		ginkgo.It("blocks modifications to nodes", func(ctx context.Context) {
			var nodes v1.NodeList
			selectInfraNodes := resources.WithLabelSelector(labels.FormatLabels(map[string]string{"node-role.kubernetes.io": "infra"}))
			// err = client.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: selectInfraNodes.String()})
			err = dedicatedAdmink8s.List(ctx, &nodes, selectInfraNodes)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(nodes.Items)).Should(BeNumerically(">", 0), "failed to find infra nodes")

			node := nodes.Items[0]
			node.SetLabels(map[string]string{"osde2e": ""})
			// _, err = client.CoreV1().Nodes().Update(ctx, &node, metav1.UpdateOptions{})
			err = dedicatedAdmink8s.Update(ctx, &node)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("forbidden"))
		})

		// TODO: test "system:serviceaccounts:openshift-backplane-cee" group can use NetNamespace CR

		ginkgo.It("allows dedicated-admin to manage CustomDomain CRs", func(ctx context.Context) {
			dynamicClient, err := dynamic.NewForConfig(client.GetConfig())
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

		ginkgo.It("allows backplane-cluster-admin to manage MustGather CRs", func(ctx context.Context) {
			dynamicClient, err := dynamic.NewForConfig(client.GetConfig())
			Expect(err).ShouldNot(HaveOccurred(), "failed creating the dynamic client: %w", err)

			mgc := dynamicClient.Resource(schema.GroupVersionResource{
				Group:    "managed.openshift.io",
				Version:  "v1alpha1",
				Resource: "mustgathers",
			}).Namespace("current-project-namespace")

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

	ginkgo.Describe("sre-hiveownership-validation", ginkgo.Ordered, func() {
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

		ginkgo.BeforeAll(func(ctx context.Context) {
			// clusterAdmink8s, err = client.Impersonate("system:admin", "cluster-admins")
			// Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated cluster admin client")
			managedCRQ = newTestCRQ("managed" + quotaName)
			err = clusterAdmink8s.Create(ctx, managedCRQ)
			Expect(err).NotTo(HaveOccurred())
		})

		ginkgo.AfterAll(func(ctx context.Context) {
			// asAdmin := h.AsClusterAdmin()
			err := clusterAdmink8s.Delete(ctx, managedCRQ)
			Expect(err).NotTo(HaveOccurred())
		})

		ginkgo.It("blocks deletion of managed ClusterResourceQuotas", func(ctx context.Context) {
			// client := h.AsDedicatedAdmin()
			// dedicatedAdmink8s, err := client.Impersonate("dedicated-admins")
			// Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated dedicated admin client")
			err = dedicatedAdmink8s.Delete(ctx, managedCRQ)
			Expect(errors.IsForbidden(err)).To(BeTrue())
			// client := h.AsUser()
			err = client.Delete(ctx, managedCRQ)
			Expect(errors.IsForbidden(err)).To(BeTrue())
		})

		ginkgo.It("allows a member of SRE to update managed ClusterResourceQuotas", func(ctx context.Context) {
			// client := h.AsUser("backplane-cluster-admin")
			userk8s, err := client.Impersonate("backplane-cluster-admin")
			managedCRQ.SetLabels(map[string]string{"osde2e": ""})
			err = userk8s.Update(ctx, managedCRQ)
			Expect(err).NotTo(HaveOccurred())
		})

		ginkgo.It("allows dedicated-admins can manage unmanaged ClusterResourceQuotas", func(ctx context.Context) {
			unmanagedCRQ := newTestCRQ("openshift" + quotaName)

			err := dedicatedAdmink8s.Create(ctx, unmanagedCRQ)
			expect.NoError(err)

			unmanagedCRQ.SetLabels(map[string]string{"osde2e": ""})
			err = dedicatedAdmink8s.Update(ctx, unmanagedCRQ)
			expect.NoError(err)

			err = dedicatedAdmink8s.Delete(ctx, unmanagedCRQ)
			expect.NoError(err)
		})
	})

	ginkgo.Describe("sre-scc-validation", func() {
		ginkgo.It("blocks modifications to default SecurityContextConstraints", func(ctx context.Context) {
			// dedicatedAdmink8s, err := client.Impersonate("test-user@redhat.com", "dedicated-admins")
			// Expect(err).ShouldNot(HaveOccurred(), "Unable to setup impersonated dedicated admin client")

			scc := &securityv1.SecurityContextConstraints{ObjectMeta: metav1.ObjectMeta{Name: "privileged"}}
			scc.SetLabels(map[string]string{"osde2e": ""})

			err = dedicatedAdmink8s.Update(ctx, scc)
			Expect(errors.IsForbidden(err)).To(BeTrue())

			err = dedicatedAdmink8s.Delete(ctx, scc)
			Expect(errors.IsForbidden(err)).To(BeTrue())
		})
	})

	ginkgo.Describe("sre-namespace-validation", ginkgo.Ordered, func() {
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
			// clusterAdmink8s, err = client.Impersonate("system:admin", "cluster-admins")
			err := clusterAdmink8s.Get(ctx, name, "", &v1.Namespace{})
			if errors.IsNotFound(err) {
				err = client.Create(ctx, &v1.Namespace{
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

		updateNamespace := func(ctx context.Context, name string, user string, groups ...string) error {
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

		ginkgo.BeforeAll(func(ctx context.Context) {
			for namespace, create := range privilegedNamespaces {
				if create {
					createNamespace(ctx, namespace)
				}
			}
			createNamespace(ctx, nonPrivilegedNamespace)
		})

		ginkgo.AfterAll(func(ctx context.Context) {
			for namespace, del := range privilegedNamespaces {
				if del {
					deleteNamespace(ctx, namespace)
				}
			}
			deleteNamespace(ctx, nonPrivilegedNamespace)
		})

		ginkgo.It("blocks dedicated admins from managing privileged namespaces", func(ctx context.Context) {
			for namespace := range privilegedNamespaces {
				err := updateNamespace(ctx, namespace, testUser, "dedicated-admins")
				expect.Forbidden(err)
			}
		})

		ginkgo.It("block non privileged users from managing privileged namespaces", func(ctx context.Context) {
			for namespace := range privilegedNamespaces {
				err := updateNamespace(ctx, namespace, testUser)
				expect.Forbidden(err)
			}
		})

		ginkgo.It("allows privileged users to manage all namespaces", func(ctx context.Context) {
			for _, user := range privilegedUsers {
				for namespace := range privilegedNamespaces {
					err := updateNamespace(ctx, namespace, user)
					expect.NoError(err)
				}

				err := updateNamespace(ctx, nonPrivilegedNamespace, user)
				expect.NoError(err)
			}
		})

		ginkgo.It("allows non privileged users to manage non privileged namespaces", func(ctx context.Context) {
			err := updateNamespace(ctx, nonPrivilegedNamespace, testUser, "dedicated-admins")
			expect.NoError(err)
		})
	})

	ginkgo.Describe("sre-prometheusrule-validation", func() {
		const privilegedNamespace = "openshift-backplane"

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

		ginkgo.DescribeTable(
			"blocks users from creating PrometheusRules in privileged namespaces",
			func(ctx context.Context, user string) {
				rule := newPrometheusRule(privilegedNamespace)
				// ruleClient := client.Resource(schema.GroupVersionResource{
				// 	Group:    "monitoring.coreos.com",
				// 	Version:  "v1",
				// 	Resource: "prometheusrules",
				// }).Namespace(privilegedNamespace)

				// _, err = ruleClient.Create(ctx, rule, metav1.CreateOptions{})

				err := client.Create(ctx, rule)
				Expect(err.Error()).To(ContainSubstring("forbidden"))
			},
			ginkgo.Entry("as dedicated-admin", "dedicated-admin"),
			ginkgo.Entry("as random user", "majora"),
		)

		ginkgo.It("allows backplane-cluster-admin to manage PrometheusRules in all namespaces", func(ctx context.Context) {
			userk8s, err := client.Impersonate("backplane-cluster-admin")
			Expect(err).NotTo(HaveOccurred())

			rule := newPrometheusRule(privilegedNamespace)
			// ruleClient := client.Resource(schema.GroupVersionResource{
			// 	Group:    "monitoring.coreos.com",
			// 	Version:  "v1",
			// 	Resource: "prometheusrules",
			// }).Namespace(privilegedNamespace)

			err = userk8s.Create(ctx, rule)
			// _, err = ruleClient.Create(ctx, rule, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			err = client.Delete(ctx, rule)
			// err = ruleClient.Delete(ctx, "prometheus-example-app", metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			rule = newPrometheusRule("current-project-namespace")
			err = client.Create(ctx, rule)
			Expect(err).NotTo(HaveOccurred())
			err = client.Delete(ctx, rule)
			Expect(err).NotTo(HaveOccurred())
		})

		ginkgo.It("allows non-privileged users to manage PrometheusRules in non-privileged namespaces", func(ctx context.Context) {
			// dedicatedAdmink8s, err = client.Impersonate("test-user@redhat.com", "dedicated-admins")
			// Expect(err).NotTo(HaveOccurred())

			rule := newPrometheusRule("current-project-namespace")
			// ruleClient := client.Resource(schema.GroupVersionResource{
			// 	Group:    "monitoring.coreos.com",
			// 	Version:  "v1",
			// 	Resource: "prometheusrules",
			// }).Namespace("current-project-namespace")

			err = dedicatedAdmink8s.Create(ctx, rule)
			Expect(err).NotTo(HaveOccurred())

			err = dedicatedAdmink8s.Delete(ctx, rule)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
