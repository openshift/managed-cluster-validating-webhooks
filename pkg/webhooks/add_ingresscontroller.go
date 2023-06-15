package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/ingresscontroller"
)

func init() {
	Register(ingresscontroller.WebhookName, func() Webhook { return ingresscontroller.NewWebhook() })
}
