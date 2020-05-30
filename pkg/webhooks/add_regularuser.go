package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/regularuser"
)

func init() {
	Register(regularuser.WebhookName, func() Webhook { return regularuser.NewWebhook() })
}
