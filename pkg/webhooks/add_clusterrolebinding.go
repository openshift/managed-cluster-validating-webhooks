package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/clusterrolebinding"
)

func init() {
	Register(clusterrolebinding.WebhookName, func() Webhook { return clusterrolebinding.NewWebhook() })
}
