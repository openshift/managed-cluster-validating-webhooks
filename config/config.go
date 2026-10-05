package config

const (
	// I know this isn't the operator's name but so much stuff has been coded to use this...
	OperatorName      = "validation-webhook"
	OperatorNamespace = "openshift-validation-webhook"

	ValidationWebhookConfigMapName = "validation-webhook-config"
	CCSCPMSResizeConfigKey         = "enableCCSCPMSResize"
	ValidationWebhookConfigMount   = "/etc/validation-webhook-config"
)
