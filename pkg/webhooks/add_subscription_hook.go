package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/subscription"
)

func init() {
	Register(subscription.WebhookName, func() Webhook { return subscription.NewWebhook() })
}
