package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/namespace"
)

func init() {
	Register(namespace.WebhookName, func() Webhook { return namespace.NewWebhook() })
}
