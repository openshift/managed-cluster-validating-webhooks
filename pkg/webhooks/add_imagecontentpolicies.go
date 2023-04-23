package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/imagecontentpolicies"
)

func init() {
	Register(imagecontentpolicies.WebhookName, func() Webhook { return imagecontentpolicies.NewWebhook() })
}
