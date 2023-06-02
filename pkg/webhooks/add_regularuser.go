package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/regularuser/common"
)

func init() {
	Register(common.WebhookName, func() Webhook { return common.NewWebhook() })
}
