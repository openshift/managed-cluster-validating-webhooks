package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/techpreviewnoupgrade"
)

func init() {
	Register(techpreviewnoupgrade.WebhookName, func() Webhook { return techpreviewnoupgrade.NewWebhook() })
}
