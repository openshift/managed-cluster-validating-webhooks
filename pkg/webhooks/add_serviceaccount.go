package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/serviceaccount"
)

func init() {
	Register(serviceaccount.WebhookName, func() Webhook { return serviceaccount.NewWebhook() })
}
