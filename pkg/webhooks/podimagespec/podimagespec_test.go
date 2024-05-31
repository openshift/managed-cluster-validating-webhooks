package podimagespec

import (
	"context"
	"reflect"
	"testing"

	registryv1 "github.com/openshift/api/imageregistry/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type outputImageSpecRegex struct {
	matched   bool
	namespace string
	image     string
	tag       string
}

func newMockRegistry(obs ...client.Object) (client.Client, error) {
	s := runtime.NewScheme()
	if err := registryv1.Install(s); err != nil {
		return nil, err
	}

	return fake.NewClientBuilder().WithScheme(s).WithObjects(obs...).Build(), nil
}

func TestCheckImageRegistryStatus(t *testing.T) {
	tests := []struct {
		name     string
		config   *registryv1.Config
		expected bool
	}{
		{
			name: "test",
			config: &registryv1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name: "notfound",
				},
				Spec:   registryv1.ImageRegistrySpec{},
				Status: registryv1.ImageRegistryStatus{},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		s := NewWebhook()
		s.kubeClient, _ = newMockRegistry(test.config)
		actual, _ := s.checkImageRegistryStatus(context.Background())
		if actual != test.expected {
			t.Error("failed")
		}
	}

}

func TestCheckContainerImageSpecByRegex(t *testing.T) {

	tests := []struct {
		name      string
		imagespec string
		expected  outputImageSpecRegex
	}{
		{
			name:      "test uninteresting short imagespec",
			imagespec: "ubuntu",
			expected: outputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		{
			name:      "test uninteresting short tagged imagespec",
			imagespec: "ubuntu:latest",
			expected: outputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		{
			name:      "test uninteresting fully qualified tagged imagespec",
			imagespec: "docker.io/library/ubuntu:latest",
			expected: outputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		{
			name:      "test uninteresting fully qualified SHA imagespec",
			imagespec: "quay.io/openshift-release-dev/ocp-release@sha256:4dbe2a75a516a947eab036ef6a1d086f1b1610f6bd21c6ab5f95db68ec177ea2",
			expected: outputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		/// TODO: Need to add functionality to replace this with a fully qualified quay.io image.
		{
			name:      "test interesting fully qualified SHA imagespec",
			imagespec: "image-registry.openshift-image-registry.svc:5000/openshift/cli@sha256:4dbe2a75a516a947eab036ef6a1d086f1b1610f6bd21c6ab5f95db68ec177ea2",
			expected: outputImageSpecRegex{
				matched:   false,
				namespace: "",
				image:     "",
				tag:       "",
			},
		},
		{
			name:      "test interesting fully qualified tagged imagespec",
			imagespec: "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest",
			expected: outputImageSpecRegex{
				matched:   true,
				namespace: "openshift",
				image:     "cli",
				tag:       "latest",
			},
		},
	}

	for _, test := range tests {
		actual := outputImageSpecRegex{}
		actual.matched, actual.namespace, actual.image, actual.tag = checkContainerImageSpecByRegex(test.imagespec)
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("TestCheckContainerImageSpecByRegex() %s -\n imagespec: %s \n actual: %v\n expected: %v\n", test.name, test.imagespec, actual, test.expected)
		}
	}

}

func TestPodContainsContainerRegexMatch(t *testing.T) {
	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected bool
	}{
		{
			name:     "test empty pod",
			pod:      &corev1.Pod{},
			expected: false,
		},
		{
			name: "test pod with cli image in containers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Image: "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest"},
					},
				},
				Status: corev1.PodStatus{},
			},
			expected: true,
		},
		{
			name: "test pod with cli image in initcontainers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{Image: "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest"},
					},
				},
				Status: corev1.PodStatus{},
			},
			expected: true,
		},
		{
			name: "test pod with uninteresting image in containers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Image: "ubuntu"},
					},
				},
				Status: corev1.PodStatus{},
			},
			expected: false,
		},
		{
			name: "test pod with uninteresting image in initcontainers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{Image: "ubuntu"},
					},
				},
				Status: corev1.PodStatus{},
			},
			expected: false,
		},
		{
			name: "test pod with cli image in initcontainers and uninteresting in containers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Image: "ubuntu"},
					},
					InitContainers: []corev1.Container{
						{Image: "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest"},
					},
				},
				Status: corev1.PodStatus{},
			},
			expected: true,
		},
		{
			name: "test pod with cli image in containers and uninteresting in initcontainers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Image: "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest"},
					},
					InitContainers: []corev1.Container{
						{Image: "ubuntu"},
					},
				},
				Status: corev1.PodStatus{},
			},
			expected: true,
		},
		{
			name: "test pod with cli image in containers and initcontainers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Image: "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest"},
					},
					InitContainers: []corev1.Container{
						{Image: "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest"},
					},
				},
				Status: corev1.PodStatus{},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		actual := podContainsContainerRegexMatch(test.pod)
		if actual != test.expected {
			t.Errorf("TestPodContainsContainerRegexMatch() %s -\n pod: %v \n actual: %t\n expected: %t\n", test.name, test.pod, actual, test.expected)
		}
	}

}
