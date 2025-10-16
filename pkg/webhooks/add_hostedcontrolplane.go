package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/hostedcontrolplane"
)

func init() {
	Register(hostedcontrolplane.WebhookName, func() Webhook { return hostedcontrolplane.NewWebhook() })
}
