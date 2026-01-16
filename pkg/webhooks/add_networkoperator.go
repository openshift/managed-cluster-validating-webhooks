package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/networkoperator"
)

func init() {
	Register(networkoperator.WebhookName, func() Webhook { return networkoperator.NewWebhook() })
}
