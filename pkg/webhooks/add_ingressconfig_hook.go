package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/ingressconfig"
)

func init() {
	Register(ingressconfig.WebhookName, func() Webhook { return ingressconfig.NewWebhook() })
}
