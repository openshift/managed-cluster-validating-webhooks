package certinjector

import (
	"context"
	"fmt"
	"testing"

	admissionregv1 "k8s.io/api/admissionregistration/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubernetes "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/pointer"
)

const (
	// Amazon_Root_CA_1.pem
	certString string = `-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----
`
)

func newTestClient(objs ...runtime.Object) *CertInjector {
	s := runtime.NewScheme()
	err := admissionregv1.AddToScheme(s)
	if err != nil {
		panic(err.Error())
	}
	err = corev1.AddToScheme((s))
	if err != nil {
		panic(err.Error())
	}
	clientset := kubernetes.NewSimpleClientset(objs...)

	d := &CertInjector{
		scheme:    *s,
		clientset: clientset,
	}

	return d
}

func createConfigMap(name, namespace string, annotations, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: annotations,
			Name:        name,
			Namespace:   namespace,
		},
		Data: data,
	}
}

func createValidatingWebhookConfiguration(name, namespace string, annotations map[string]string) *admissionregv1.ValidatingWebhookConfiguration {
	scope := admissionregv1.ClusterScope
	return &admissionregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Webhooks: []admissionregv1.ValidatingWebhook{
			{
				Rules: []admissionregv1.RuleWithOperations{
					{
						Operations: []admissionregv1.OperationType{"UPDATE"},
						Rule: admissionregv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"*"},
							Resources:   []string{"namespaces"},
							Scope:       &scope,
						},
					},
				},
				Name: fmt.Sprintf("%s-hook.managed.openshift.io", name),
				ClientConfig: admissionregv1.WebhookClientConfig{
					Service: &admissionregv1.ServiceReference{
						Namespace: namespace,
						Path:      pointer.StringPtr(fmt.Sprintf("/%s-hook", name)),
						Name:      name,
					},
				},
			},
		},
	}
}
func TestGetCACertFromConfigMap(t *testing.T) {
	cm := createConfigMap("with", "test",
		map[string]string{"service.beta.openshift.io/inject-cabundle": "true"},
		map[string]string{"service-ca.crt": certString})
	injector := newTestClient(cm)
	cert, err := injector.getCACert("with", "test")
	if err != nil {
		t.Fatalf("Unexpected error while getting CA cert: %s", err.Error())
	}
	if cert != certString {
		t.Fatalf("Cert mismatch. Got %s, expected %s", cert, certString)
	}
}

func TestGetMissingCACertFromConfigMap(t *testing.T) {
	cm := createConfigMap("with", "test",
		map[string]string{"service.beta.openshift.io/inject-cabundle": "true"},
		map[string]string{})
	injector := newTestClient(cm)
	cert, err := injector.getCACert("with", "test")
	if err == nil || cert != "" {
		t.Fatalf("Unexpected to see that there's no CA Cert in this ConfigMap, but we got no error back. wat")
	}
}

func TestGetValidatingWebhooks(t *testing.T) {
	withAnnotation := createValidatingWebhookConfiguration("with", "test", map[string]string{"managed.openshift.io/inject-cabundle-from": "test/with"})
	withoutAnnotation := createValidatingWebhookConfiguration("without", "test", map[string]string{})
	injector := newTestClient(withAnnotation, withoutAnnotation)
	hooks, err := injector.getValidatingWebhooks("managed.openshift.io/inject-cabundle-from")
	if err != nil {
		t.Fatalf("Got an unexpected error: %s", err.Error())
	}
	if len(hooks) != 1 {
		t.Fatalf("Expected to get 1 hook, got %d", len(hooks))
	}
}

func TestInject(t *testing.T) {
	withAnnotation := createValidatingWebhookConfiguration("with", "test", map[string]string{"managed.openshift.io/inject-cabundle-from": "test/with"})
	withoutAnnotation := createValidatingWebhookConfiguration("without", "test", map[string]string{})
	cm := createConfigMap("with", "test",
		map[string]string{"service.beta.openshift.io/inject-cabundle": "true"},
		map[string]string{"service-ca.crt": certString})
	injector := newTestClient(withAnnotation, withoutAnnotation, cm)
	err := injector.Inject()
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	// now try to reload the one with the annotation and see if it has the cert info
	webhook, err := injector.clientset.
		AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		Get(context.TODO(), "with", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	webhook, err = injector.clientset.
		AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		Get(context.TODO(), webhook.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	if len(webhook.Webhooks[0].ClientConfig.CABundle) == 0 {
		t.Fatalf("ValidatingWebhookConfiguration %s, webhook %s missing CA Bundle. Value: %s", webhook.GetName(), webhook.Webhooks[0].Name, string(webhook.Webhooks[0].ClientConfig.CABundle))

	}

}
