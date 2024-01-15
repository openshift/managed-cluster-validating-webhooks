package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/customresourcedefinitions"
)

func init() {
	Register(customresourcedefinitions.WebhookName, func() Webhook { return customresourcedefinitions.NewWebhook() })
}
