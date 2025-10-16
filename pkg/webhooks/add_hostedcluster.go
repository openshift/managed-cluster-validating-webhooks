package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/hostedcluster"
)

func init() {
	Register(hostedcluster.WebhookName, func() Webhook { return hostedcluster.NewWebhook() })
}
