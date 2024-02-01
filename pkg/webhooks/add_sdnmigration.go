package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/sdnmigration"
)

func init() {
	Register(sdnmigration.WebhookName, func() Webhook { return sdnmigration.NewWebhook() })
}
