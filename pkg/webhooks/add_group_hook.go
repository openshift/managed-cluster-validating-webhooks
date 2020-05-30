package webhooks

import "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/group"

func init() {
	Register(group.WebhookName, func() Webhook { return group.NewWebhook() })
}
