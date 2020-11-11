package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/nodelabels"
)

func init() {
	Register(nodelabels.WebhookName, func() Webhook { return nodelabels.NewWebhook() })
}
