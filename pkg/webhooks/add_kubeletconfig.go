package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/kubeletconfig"
)

func init() {
	Register(kubeletconfig.WebhookName, func() Webhook { return kubeletconfig.NewWebhook() })
}