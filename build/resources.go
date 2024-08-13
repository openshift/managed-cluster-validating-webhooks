package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	templatev1 "github.com/openshift/api/template/v1"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/syncset"
	webhooks "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks"
	utils "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"

	"github.com/ghodss/yaml"
)

const (
	serviceName        string = "validation-webhook"
	serviceAccountName string = "validation-webhook"
	roleName           string = "validation-webhook"
	prometheusRoleName string = "prometheus-k8s"
	repoName           string = "managed-cluster-validating-webhooks"
	// Role and Binding for reading cluster-config-v1 config map...
	clusterConfigRole        string = "config-v1-reader-wh"
	clusterConfigRoleBinding string = "validation-webhook-cluster-config-v1-reader"
	// Used to define what phase a resource should be deployed in by package-operator
	pkoPhaseAnnotation string = "package-operator.run/phase"
	// Defines the 'rbac' package-operator phase for any resources related to RBAC
	rbacPhase string = "rbac"
	// Defines the 'deploy' package-operator phase for any resources related to MCVW deployment
	deployPhase string = "deploy"
	// Defines the 'config' package-operator phase for any resources related to MCVW configuration
	configPhase string = "config"
	// Defines the 'webhooks' package-operator phase for any resources related to MCVW configuration
	webhooksPhase string = "webhooks"
	// Defines the label for targeting control plane taints/tolerations
	controlPlaneLabel = "hypershift.openshift.io/control-plane"
	// Defines the label for targeting hypershift cluster taints/tolerations
	hsControlPlaneLabel = "hypershift.openshift.io/hosted-control-plane"
	// Defines the label for targeting hypershift control plane taints/tolerations
	hsClusterLabel = "hypershift.openshift.io/cluster"
	//caBundle annotation
	caBundleAnnotation = "service.beta.openshift.io/inject-cabundle"
)

var (
	listenPort    = flag.Int("port", 5000, "On which port should the Webhook binary listen? (Not the Service port)")
	secretName    = flag.String("secretname", "webhook-cert", "Secret where TLS certs are created")
	caBundleName  = flag.String("cabundlename", "webhook-cert", "ConfigMap where CA cert is created")
	templateFile  = flag.String("syncsetfile", "", "Path to where the SelectorSyncSet template should be written")
	packageDir    = flag.String("packagedir", "", "Path to where the package manifest and resources should be written")
	replicas      = flag.Int("replicas", 2, "Number of replicas for Hypershift-based MCVW deployment")
	excludes      = flag.String("exclude", "debug-hook", "Comma-separated list of webhook names to skip")
	only          = flag.String("only", "", "Only include these comma-separated webhooks")
	showHookNames = flag.Bool("showhooks", false, "Print registered webhook names and exit")

	namespace = flag.String("namespace", "openshift-validation-webhook", "In what namespace should resources exist?")

	sssLabels = map[string]string{
		"managed.openshift.io/gitHash":     "${IMAGE_TAG}",
		"managed.openshift.io/gitRepoName": "${REPO_NAME}",
		"managed.openshift.io/osd":         "true",
	}
)

func createNamespace() *corev1.Namespace {
	return &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: *namespace,
			Labels: map[string]string{
				"openshift.io/cluster-monitoring": "true",
			},
		},
	}
}

func createServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: *namespace,
		},
	}
}

func createRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: *namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"services",
				},
				Verbs: []string{
					"*",
				},
			},
			{
				APIGroups: []string{
					"monitoring.coreos.com",
				},
				Resources: []string{
					"servicemonitors",
				},
				Verbs: []string{
					"*",
				},
			},
		},
	}
}

func createRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s:%s", roleName, serviceAccountName),
			Namespace: *namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: *namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Name:     roleName,
			Kind:     "Role",
			APIGroup: rbacv1.GroupName,
		},
	}
}

func createClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"imageregistry.operator.openshift.io",
				},
				Resources: []string{
					"configs",
				},
				Verbs: []string{
					"get",
				},
			},
		},
	}
}

func createClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s:%s", roleName, serviceAccountName),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: *namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Name:     roleName,
			Kind:     "ClusterRole",
			APIGroup: rbacv1.GroupName,
		},
	}
}

func createClusterConfigRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterConfigRole,
			Namespace: "kube-system",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"configmaps",
				},
				Verbs: []string{
					"get",
				},
				ResourceNames: []string{
					"cluster-config-v1",
				},
			},
		},
	}
}

func createClusterConfigRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterConfigRoleBinding,
			Namespace: "kube-system",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: *namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Name:     clusterConfigRole,
			Kind:     "Role",
			APIGroup: rbacv1.GroupName,
		},
	}
}

func createPrometheusRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      prometheusRoleName,
			Namespace: *namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"services",
					"endpoints",
					"pods",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
		},
	}
}

func createPromethusRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-k8s",
			Namespace: *namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "prometheus-k8s",
				Namespace: "openshift-monitoring",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Name:     prometheusRoleName,
			Kind:     "Role",
			APIGroup: rbacv1.GroupName,
		},
	}
}

func createServiceMonitor() *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceMonitor",
			APIVersion: "monitoring.coreos.com/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "validating-webhook-metrics",
			Namespace: *namespace,
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Endpoints: []monitoringv1.Endpoint{
				{
					BearerTokenSecret: corev1.SecretKeySelector{
						Key: "",
					},
					Port: "metrics",
				},
			},
			NamespaceSelector: monitoringv1.NamespaceSelector{
				MatchNames: []string{
					*namespace,
				},
			},
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": serviceName,
				},
			},
		},
	}
}

func createCACertConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				// service.beta.openshift.io/inject-cabundle annotation informs
				// service-ca-operator to insert a CA cert bundle in this ConfigMap,
				// later mounted by the Pod for secure communications from Kubernetes
				// API server.
				"service.beta.openshift.io/inject-cabundle": "true",
			},
			Name:      "webhook-cert",
			Namespace: *namespace,
		},
	}
}

func createPackagedCACertConfigMap(phase string) *corev1.ConfigMap {
	cm := createCACertConfigMap()
	cm.Annotations[pkoPhaseAnnotation] = phase
	cm.Namespace = ""
	return cm
}

func createPackagedDeployment(replicas int32, phase string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": "validation-webhook",
			},
			Name: "validation-webhook",
			Annotations: map[string]string{
				pkoPhaseAnnotation: phase,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "validation-webhook",
				},
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 1,
					},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "validation-webhook",
					},
				},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
								{
									Preference: corev1.NodeSelectorTerm{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      hsControlPlaneLabel,
												Operator: corev1.NodeSelectorOpIn,
												Values: []string{
													"true",
												},
											},
										},
									},
									Weight: 50,
								},
								{
									Preference: corev1.NodeSelectorTerm{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      hsClusterLabel,
												Operator: corev1.NodeSelectorOpIn,
												Values: []string{
													"{{.package.metadata.namespace}}",
												},
											},
										},
									},
									Weight: 100,
								},
							},
						},
						PodAffinity: &corev1.PodAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
								{
									Weight: 100,
									PodAffinityTerm: corev1.PodAffinityTerm{
										LabelSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{
												hsControlPlaneLabel: "{{.package.metadata.namespace}}",
											},
										},
										TopologyKey: "kubernetes.io/hostname",
									},
								},
							},
						},
						PodAntiAffinity: &corev1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"app": "validation-webhook",
										},
									},
									TopologyKey: "topology.kubernetes.io/zone",
								},
							},
						},
					},
					Tolerations: []corev1.Toleration{
						{
							Key:      controlPlaneLabel,
							Operator: corev1.TolerationOpEqual,
							Value:    "true",
							Effect:   corev1.TaintEffectNoSchedule,
						},
						{
							Key:      hsControlPlaneLabel,
							Operator: corev1.TolerationOpEqual,
							Value:    "true",
							Effect:   corev1.TaintEffectNoSchedule,
						},
						{
							Key:      hsClusterLabel,
							Operator: corev1.TolerationOpEqual,
							Value:    "{{.package.metadata.namespace}}",
							Effect:   corev1.TaintEffectNoSchedule,
						},
					},
					RestartPolicy: corev1.RestartPolicyAlways,
					Volumes: []corev1.Volume{
						{
							Name: "service-certs",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: *secretName,
								},
							},
						},
						{
							Name: "service-ca",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: *caBundleName,
									},
								},
							},
						},
						{
							Name: "hosted-kubeconfig",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "service-network-admin-kubeconfig",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							// Since we're referencing images by digest, we don't
							// have to worry about them changing underneath us.
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "webhooks",
							Image:           "REPLACED_BY_PIPELINE",
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "service-certs",
									MountPath: "/service-certs",
									ReadOnly:  true,
								},
								{
									Name:      "service-ca",
									MountPath: "/service-ca",
									ReadOnly:  true,
								},
								{
									Name:      "hosted-kubeconfig",
									MountPath: "/etc/hosted-kubernetes",
									ReadOnly:  true,
								},
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: int32(*listenPort),
								},
							},
							Command: []string{
								"webhooks",
								"-tlskey", "/service-certs/tls.key",
								"-tlscert", "/service-certs/tls.crt",
								"-cacert", "/service-ca/service-ca.crt",
								"-tls",
							},
							Env: []corev1.EnvVar{
								{
									Name:  "KUBECONFIG",
									Value: "/etc/hosted-kubernetes/kubeconfig",
								},
							},
						},
					},
				},
			},
		},
	}
}

func createDaemonSet() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": "validation-webhook",
			},
			Name:      "validation-webhook",
			Namespace: *namespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "validation-webhook",
				},
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 1,
					},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "validation-webhook",
					},
				},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      "node-role.kubernetes.io/master",
												Operator: corev1.NodeSelectorOpIn,
												Values: []string{
													"",
												},
											},
										},
									},
								},
							},
						},
					},
					Tolerations: []corev1.Toleration{
						{
							Key:    "node-role.kubernetes.io/master",
							Value:  "",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "node-role.kubernetes.io/master",
							Value:  "",
							Effect: corev1.TaintEffectNoExecute,
						},
					},
					RestartPolicy:      corev1.RestartPolicyAlways,
					ServiceAccountName: serviceAccountName,
					Volumes: []corev1.Volume{
						{
							Name: "service-certs",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: *secretName,
								},
							},
						},
						{
							Name: "service-ca",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: *caBundleName,
									},
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							// Since we're referencing images by digest, we don't
							// have to worry about them changing underneath us.
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "webhooks",
							Image:           "${REGISTRY_IMG}@${IMAGE_DIGEST}",
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "service-certs",
									MountPath: "/service-certs",
									ReadOnly:  true,
								},
								{
									Name:      "service-ca",
									MountPath: "/service-ca",
									ReadOnly:  true,
								},
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: int32(*listenPort),
								},
							},
							Command: []string{
								"webhooks",
								"-tlskey", "/service-certs/tls.key",
								"-tlscert", "/service-certs/tls.crt",
								"-cacert", "/service-ca/service-ca.crt",
								"-tls",
							},
						},
					},
				},
			},
		},
	}
}

func createService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				// service-ca-operator annotation to correlate the Secret (containing
				// private cert infomation) back to the Service for which it was
				// created.
				"service.beta.openshift.io/serving-cert-secret-name": *secretName,
			},
			Labels: map[string]string{
				"name": serviceName,
				// hosted-cluster-config-operator label for HOSTEDCP-1063 compliance,
				// i.e., adding our webhook's service to the HCP webhook allowlist
				"hypershift.openshift.io/allow-guest-webhooks": "true",
			},
			Name:      serviceName,
			Namespace: *namespace,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app": "validation-webhook",
			},
			Ports: []corev1.ServicePort{
				{
					Name: "https",
					Port: 443,
					TargetPort: intstr.IntOrString{
						IntVal: int32(*listenPort),
						Type:   intstr.Int,
					},
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
}

func createPackagedService(phase string) *corev1.Service {
	service := createService()
	service.Annotations[pkoPhaseAnnotation] = phase
	service.Namespace = ""
	return service
}

func createPackagedValidatingWebhookConfiguration(webhook webhooks.Webhook, phase string) admissionregv1.ValidatingWebhookConfiguration {
	webhookConfiguration := createValidatingWebhookConfiguration(webhook)
	uri := webhook.GetURI()
	url := "https://" + serviceName + ".{{.package.metadata.namespace}}.svc.cluster.local" + uri
	webhookConfiguration.Annotations[pkoPhaseAnnotation] = phase
	webhookConfiguration.Annotations[caBundleAnnotation] = "false"
	webhookConfiguration.Webhooks[0].ClientConfig = admissionregv1.WebhookClientConfig{
		URL:      &url,
		CABundle: []byte("{{.config.serviceca | b64enc }}"),
	}
	return webhookConfiguration
}

// hookToResources turns a Webhook into a ValidatingWebhookConfiguration and Service.
// The Webhook is expected to implement Rules() which will return a
func createValidatingWebhookConfiguration(hook webhooks.Webhook) admissionregv1.ValidatingWebhookConfiguration {
	failPolicy := hook.FailurePolicy()
	timeout := hook.TimeoutSeconds()
	matchPolicy := hook.MatchPolicy()
	sideEffects := hook.SideEffects()

	return admissionregv1.ValidatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ValidatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("sre-%s", hook.Name()),

			Annotations: map[string]string{
				// service.beta.openshift.io/inject-cabundle annotation will instruct
				// service-ca-operator to install a CA cert in the
				// ValidatingWebhookConfiguration object, which is required for
				// Kubernetes to communicate securely to the Service.
				"service.beta.openshift.io/inject-cabundle": "true",
			},
		},
		Webhooks: []admissionregv1.ValidatingWebhook{
			{
				AdmissionReviewVersions: []string{"v1"},
				TimeoutSeconds:          &timeout,
				SideEffects:             &sideEffects,
				MatchPolicy:             &matchPolicy,
				Name:                    fmt.Sprintf("%s.managed.openshift.io", hook.Name()),
				ObjectSelector:          hook.ObjectSelector(),
				FailurePolicy:           &failPolicy,
				ClientConfig: admissionregv1.WebhookClientConfig{
					Service: &admissionregv1.ServiceReference{
						Namespace: *namespace,
						Path:      pointer.StringPtr(hook.GetURI()),
						Name:      serviceName,
					},
				},
				Rules: hook.Rules(),
			},
		},
	}
}

func createPackagedMutatingWebhookConfiguration(webhook webhooks.Webhook, phase string) admissionregv1.MutatingWebhookConfiguration {
	webhookConfiguration := createMutatingWebhookConfiguration(webhook)
	uri := webhook.GetURI()
	url := "https://" + serviceName + ".{{.package.metadata.namespace}}.svc.cluster.local" + uri
	webhookConfiguration.Annotations[pkoPhaseAnnotation] = phase
	webhookConfiguration.Annotations[caBundleAnnotation] = "false"
	webhookConfiguration.Webhooks[0].ClientConfig = admissionregv1.WebhookClientConfig{
		URL:      &url,
		CABundle: []byte("{{.config.serviceca | b64enc }}"),
	}
	return webhookConfiguration
}

func createMutatingWebhookConfiguration(hook webhooks.Webhook) admissionregv1.MutatingWebhookConfiguration {
	failPolicy := hook.FailurePolicy()
	timeout := hook.TimeoutSeconds()
	matchPolicy := hook.MatchPolicy()
	sideEffects := hook.SideEffects()

	return admissionregv1.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "MutatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("sre-%s", hook.Name()),

			Annotations: map[string]string{
				// service.beta.openshift.io/inject-cabundle annotation will instruct
				// service-ca-operator to install a CA cert in the
				// MutatingWebhookConfiguration object, which is required for
				// Kubernetes to communicate securely to the Service.
				"service.beta.openshift.io/inject-cabundle": "true",
			},
		},
		Webhooks: []admissionregv1.MutatingWebhook{
			{
				AdmissionReviewVersions: []string{"v1"},
				TimeoutSeconds:          &timeout,
				SideEffects:             &sideEffects,
				MatchPolicy:             &matchPolicy,
				Name:                    fmt.Sprintf("%s.managed.openshift.io", hook.Name()),
				ObjectSelector:          hook.ObjectSelector(),
				FailurePolicy:           &failPolicy,
				ClientConfig: admissionregv1.WebhookClientConfig{
					Service: &admissionregv1.ServiceReference{
						Namespace: *namespace,
						Path:      pointer.StringPtr(hook.GetURI()),
						Name:      serviceName,
					},
				},
				Rules: hook.Rules(),
			},
		},
	}
}

func sliceContains(needle string, haystack []string) bool {
	for _, hay := range haystack {
		if hay == needle {
			return true
		}
	}
	return false
}

func main() {
	flag.Parse()

	skip := strings.Split(*excludes, ",")
	onlyInclude := strings.Split(*only, "")

	buildSelectorSyncSet := false
	if *templateFile != "" {
		buildSelectorSyncSet = true
	}

	buildPackage := false
	if *packageDir != "" {
		buildPackage = true
	}

	if buildSelectorSyncSet {
		templateResources := syncset.SyncSetResourcesByLabelSelector{}
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createNamespace()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createServiceAccount()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createRole()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createRoleBinding()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createClusterRole()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createClusterRoleBinding()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createPrometheusRole()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createPromethusRoleBinding()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createClusterConfigRole()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createClusterConfigRoleBinding()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createServiceMonitor()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createCACertConfigMap()})
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Object: createService()})

		encodedDaemonSet, err := syncset.EncodeAndFixDaemonset(createDaemonSet())
		if err != nil {
			panic(fmt.Sprintf("couldn't marshal: %s\n", err.Error()))
		}
		templateResources.Add(utils.DefaultLabelSelector(), runtime.RawExtension{Raw: encodedDaemonSet})

		// Collect all of our webhook names and prepare to sort them all so the
		// resulting SelectorSyncSet is always sorted.
		hookNames := make([]string, 0)
		for name := range webhooks.Webhooks {
			hookNames = append(hookNames, name)
		}
		sort.Strings(hookNames)
		seen := make(map[string]bool)
		for _, hookName := range hookNames {
			hook := webhooks.Webhooks[hookName]
			if seen[hook().GetURI()] {
				panic(fmt.Sprintf("Duplicate hook URI: %s", hook().GetURI()))
			}
			seen[hook().GetURI()] = true

			if !hook().ClassicEnabled() {
				continue
			}

			// no rules...?
			if len(hook().Rules()) == 0 {
				continue
			}

			if *showHookNames {
				fmt.Println(hook().Name())
			}
			if sliceContains(hook().Name(), skip) {
				continue
			}
			if len(onlyInclude) > 0 && !sliceContains(hook().Name(), onlyInclude) {
				continue
			}

			// MutatingWebhookConfigurations have special names (e.g., service-mutation)
			if strings.HasSuffix(hookName, "-mutation") {
				templateResources.Add(hook().SyncSetLabelSelector(), runtime.RawExtension{Raw: syncset.Encode(createMutatingWebhookConfiguration(hook()))})
				continue
			}

			// Now handle all Validating webhooks
			templateResources.Add(hook().SyncSetLabelSelector(), runtime.RawExtension{Raw: syncset.Encode(createValidatingWebhookConfiguration(hook()))})
		}

		if *showHookNames {
			os.Exit(0)
		}

		selectorSyncSets := templateResources.RenderSelectorSyncSets(sssLabels)

		te := templatev1.Template{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Template",
				APIVersion: "template.openshift.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "selectorsyncset-template",
			},
			Parameters: []templatev1.Parameter{
				// IMAGE_TAG is:
				// - used to label the SSS
				// - required to generate IMAGE_DIGEST
				{
					Name:     "IMAGE_TAG",
					Required: true,
				},
				{
					Name:     "REPO_NAME",
					Required: true,
					Value:    repoName,
				},
				// REGISTRY_IMG must be supplied by the SaaS file
				{
					Name:     "REGISTRY_IMG",
					Required: true,
				},
				// IMAGE_DIGEST is populated by app-sre based on probing the image at
				// ${REGISTRY_IMG}:${IMAGE_TAG}. (${IMAGE_TAG} is generated under the covers
				// based on the channel and git hash.)
				{
					Name:     "IMAGE_DIGEST",
					Required: true,
				},
			},
			Objects: selectorSyncSets,
		}

		y, err := yaml.Marshal(te)
		if err != nil {
			panic(fmt.Sprintf("couldn't marshal: %s\n", err.Error()))
		}

		err = os.WriteFile(*templateFile, y, 0644)
		if err != nil {
			panic(fmt.Sprintf("Failed to write to %s: %s\n", *templateFile, err.Error()))
		}
	} else {
		fmt.Printf("No -syncsetfile option supplied, will not generate selector sync set\n")
	}

	if buildPackage {
		// packageResources contains all resources intended for a package-operator package, with the key
		// being the associated filename to generate
		packageResources := make([]runtime.RawExtension, 0)
		packageResources = append(packageResources, runtime.RawExtension{Object: createPackagedCACertConfigMap(configPhase)})
		packageResources = append(packageResources, runtime.RawExtension{Object: createPackagedService(deployPhase)})
		packageResources = append(packageResources, runtime.RawExtension{Object: createPackagedDeployment(int32(*replicas), deployPhase)})

		hookNames := make([]string, 0)
		for name := range webhooks.Webhooks {
			hookNames = append(hookNames, name)
		}
		sort.Strings(hookNames)
		seen := make(map[string]bool)
		for _, hookName := range hookNames {
			hook := webhooks.Webhooks[hookName]
			if seen[hook().GetURI()] {
				panic(fmt.Sprintf("Duplicate hook URI: %s", hook().GetURI()))
			}
			seen[hook().GetURI()] = true

			if !hook().HypershiftEnabled() {
				continue
			}

			// no rules...?
			if len(hook().Rules()) == 0 {
				continue
			}

			if *showHookNames {
				fmt.Println(hook().Name())
			}
			if sliceContains(hook().Name(), skip) {
				continue
			}
			if len(onlyInclude) > 0 && !sliceContains(hook().Name(), onlyInclude) {
				continue
			}

			// MutatingWebhookConfigurations have special names (e.g., service-mutation)
			if strings.HasSuffix(hookName, "-mutation") {
				encodedWebhook, err := syncset.EncodeMutatingAndFixCA(createPackagedMutatingWebhookConfiguration(hook(), webhooksPhase))
				if err != nil {
					fmt.Printf("Error encoding packaged webhook: %v\n", err)
					os.Exit(1)
				}
				packageResources = append(packageResources, runtime.RawExtension{Raw: encodedWebhook})
				continue
			}

			// Now handle all Validating webhooks
			encodedWebhook, err := syncset.EncodeValidatingAndFixCA(createPackagedValidatingWebhookConfiguration(hook(), webhooksPhase))
			if err != nil {
				fmt.Printf("Error encoding packaged webhook: %v\n", err)
				os.Exit(1)
			}
			packageResources = append(packageResources, runtime.RawExtension{Raw: encodedWebhook})
		}
		var rb strings.Builder
		for _, packageResource := range packageResources {
			resourceYaml, err := yaml.Marshal(packageResource)
			if err != nil {
				panic(fmt.Sprintf("Failed to marshal resource to string: %s", err.Error()))
			}
			rb.WriteString("---\n")
			rb.Write(resourceYaml)
		}
		fname := filepath.Join(*packageDir, "resources.yaml.gotmpl")
		err := os.WriteFile(fname, []byte(rb.String()), 0644)
		if err != nil {
			panic(fmt.Sprintf("Failed to write to %s: %s", fname, err.Error()))
		}
	} else {
		fmt.Printf("No -packagedir option supplied, will not generate package manifest\n")
	}
}
