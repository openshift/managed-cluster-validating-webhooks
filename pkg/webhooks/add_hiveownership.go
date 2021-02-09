package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/hiveownership"
)

func init() {
	Register(hiveownership.WebhookName, func() Webhook { return hiveownership.NewWebhook() })
}
