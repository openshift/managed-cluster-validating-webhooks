package webhooks

import "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/regularuser/osd"

func init() {
	Register(osd.WebhookName, func() Webhook { return osd.NewWebhook() })
}
