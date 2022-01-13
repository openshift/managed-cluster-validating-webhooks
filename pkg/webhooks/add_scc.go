package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/scc"
)

func init() {
	Register(scc.WebhookName, func() Webhook { return scc.NewWebhook() })
}
