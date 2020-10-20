package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/pod"
)

func init() {
	Register(pod.WebhookName, func() Webhook { return pod.NewWebhook() })
}
