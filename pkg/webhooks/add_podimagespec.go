package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/podimagespec"
)

func init() {
	Register(podimagespec.WebhookName, func() Webhook { return podimagespec.NewWebhook() })
}
