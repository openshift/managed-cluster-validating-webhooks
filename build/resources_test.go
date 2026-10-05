package main

import (
	"testing"

	operatorconfig "github.com/openshift/managed-cluster-validating-webhooks/config"
)

func TestCreateDaemonSetConfigMapMount(t *testing.T) {
	daemonSet := createDaemonSet()
	container := daemonSet.Spec.Template.Spec.Containers[0]

	if len(container.Env) != 0 {
		t.Fatalf("environment = %#v, want none", container.Env)
	}

	var foundMount bool
	for _, mount := range container.VolumeMounts {
		if mount.Name == "validation-webhook-config" {
			foundMount = mount.MountPath == operatorconfig.ValidationWebhookConfigMount && mount.ReadOnly
		}
	}
	if !foundMount {
		t.Fatalf("volume mounts = %#v, want read-only validation webhook config mount", container.VolumeMounts)
	}

	var foundVolume bool
	for _, volume := range daemonSet.Spec.Template.Spec.Volumes {
		if volume.Name == "validation-webhook-config" && volume.ConfigMap != nil {
			foundVolume = volume.ConfigMap.Name == operatorconfig.ValidationWebhookConfigMapName && volume.ConfigMap.Optional != nil && *volume.ConfigMap.Optional
		}
	}
	if !foundVolume {
		t.Fatalf("volumes = %#v, want optional validation webhook config ConfigMap", daemonSet.Spec.Template.Spec.Volumes)
	}
}
