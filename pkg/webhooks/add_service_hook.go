package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/service"
)

func init() {
	Register(service.WebhookName, func() Webhook { return service.NewWebhook() })
}
