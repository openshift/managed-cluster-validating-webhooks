package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/networkpolicies"
)

func init() {
	Register(networkpolicies.WebhookName, func() Webhook { return networkpolicies.NewWebhook() })
}
