package webhooks

import "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/node"

func init() {
	Register(node.WebhookName, func() Webhook { return node.NewWebhook() })
}
