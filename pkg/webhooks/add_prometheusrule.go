package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/prometheusrule"
)

func init() {
	Register(prometheusrule.WebhookName, func() Webhook { return prometheusrule.NewWebhook() })
}
