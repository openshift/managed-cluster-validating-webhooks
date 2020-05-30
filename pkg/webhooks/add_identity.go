package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/identity"
)

func init() {
	Register(identity.WebhookName, func() Webhook { return identity.NewWebhook() })
}
