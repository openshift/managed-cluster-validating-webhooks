package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/clusterlogging"
)

func init() {
	Register(clusterlogging.WebhookName, func() Webhook { return clusterlogging.NewWebhook() })
}
