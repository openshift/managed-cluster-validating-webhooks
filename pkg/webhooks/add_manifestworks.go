package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/manifestworks"
)

func init() {
	Register(manifestworks.WebhookName, func() Webhook { return manifestworks.NewWebhook() })
}
