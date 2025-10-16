package webhooks

import webhooks "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/hcpnamespace"

func init() {
	Register(webhooks.WebhookName, func() Webhook { return webhooks.NewWebhook() })
}
