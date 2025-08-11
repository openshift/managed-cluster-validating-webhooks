package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/clusterrole"
)

func init() {
	Register(clusterrole.WebhookName, func() Webhook { return clusterrole.NewWebhook() })
}
