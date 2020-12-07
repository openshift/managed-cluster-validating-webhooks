package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/user"
)

func init() {
	Register(user.WebhookName, func() Webhook { return user.NewWebhook() })
}
