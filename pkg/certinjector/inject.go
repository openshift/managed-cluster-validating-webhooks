package certinjector

import (
	"context"
	"fmt"
	"strings"
	"sync"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// CertInjector will give a way to inject cert information into ValidationWebhookConfiguration Kubernets objects
type CertInjector struct {
	mu        sync.Mutex
	clientset kubernetes.Interface
	scheme    runtime.Scheme
}

func NewCertInjector() (*CertInjector, error) {
	scheme := runtime.NewScheme()
	err := admissionregv1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset := kubernetes.NewForConfigOrDie(config)
	return &CertInjector{
		clientset: clientset,
		scheme:    *scheme,
	}, nil
}

func (c *CertInjector) getCACert(name, namespace string) (string, error) {
	cm, err := c.clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, v1.GetOptions{})
	if err != nil {
		return "", err
	}
	if _, ok := cm.Data["service-ca.crt"]; !ok {
		return "", fmt.Errorf("No service-ca.crt found in ConfigMap")
	}
	return cm.Data["service-ca.crt"], nil
}

// getValidatingWebhooks returns all ValidatingWebhooks that have the
// annotationKey present
func (c *CertInjector) getValidatingWebhooks(annotationKey string) ([]admissionregv1.ValidatingWebhookConfiguration, error) {
	ret := make([]admissionregv1.ValidatingWebhookConfiguration, 0)
	hooks, err := c.clientset.
		AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		List(context.TODO(), v1.ListOptions{})
	if err != nil {
		return ret, err
	}

	for _, hook := range hooks.Items {
		if _, ok := hook.Annotations[annotationKey]; ok {
			ret = append(ret, hook)
		}
	}
	return ret, nil
}

func (c *CertInjector) Inject() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	allHooks, err := c.getValidatingWebhooks("managed.openshift.io/inject-cabundle-from")
	if err != nil {
		return err
	}
	for i := range allHooks {

		src := allHooks[i].Annotations["managed.openshift.io/inject-cabundle-from"]
		// need to inject from "src"
		split := strings.Split(src, "/")
		namespace := split[0]
		configMapSource := split[1]

		cert, err := c.getCACert(configMapSource, namespace)
		if err != nil {
			return err
		}
		for j := range allHooks[i].Webhooks {
			if string(allHooks[i].Webhooks[j].ClientConfig.CABundle) != cert {
				allHooks[i].Webhooks[j].ClientConfig.CABundle = []byte(cert)
			}
		}
		_, err = c.clientset.
			AdmissionregistrationV1().
			ValidatingWebhookConfigurations().
			Update(context.TODO(), &allHooks[i], v1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}
