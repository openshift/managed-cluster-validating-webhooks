package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/clusterlogging"
	hookconfig "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/hiveownership"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/namespace"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/pod"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/regularuser"
)

func RegisterWebhooks() {
	hookconfig.GetManagedNamespaces()

	Register(namespace.WebhookName, func() Webhook { return namespace.NewWebhook() })
	Register(pod.WebhookName, func() Webhook { return pod.NewWebhook() })
	Register(clusterlogging.WebhookName, func() Webhook { return clusterlogging.NewWebhook() })
	Register(hiveownership.WebhookName, func() Webhook { return hiveownership.NewWebhook() })
	Register(regularuser.WebhookName, func() Webhook { return regularuser.NewWebhook() })
}
