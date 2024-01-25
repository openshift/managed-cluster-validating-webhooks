package webhooks

import (
	"context"
	"log"

	"github.com/openshift/managed-cluster-validating-webhooks/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/node"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const allowWorkerNodeCordonConfigMapName = "allow-worker-node-cordon"

func init() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Println("failed to load config for feature flag, running node webhook without the feature flag")
		Register(node.WebhookName, func() Webhook { return node.NewWebhook(false) })
		return
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Println("failed to build kube client for feature flag, running node webhook without the feature flag")
		Register(node.WebhookName, func() Webhook { return node.NewWebhook(false) })
		return
	}

	if _, err := client.CoreV1().ConfigMaps(config.OperatorNamespace).Get(context.TODO(), allowWorkerNodeCordonConfigMapName, metav1.GetOptions{}); err != nil {
		// The Configmap does not exist or we ran into errors looking for it
		// Assume this feature flag should be off
		Register(node.WebhookName, func() Webhook { return node.NewWebhook(false) })
		return
	}

	// The ConfigMap exists! Turn on the feature flag
	Register(node.WebhookName, func() Webhook { return node.NewWebhook(true) })
}
