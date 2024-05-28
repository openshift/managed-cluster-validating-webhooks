package podimagespec

import (
	"context"
	"testing"

	configv1 "github.com/openshift/api/imageregistry/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func NewMock(obs ...client.Object) (client.Client, error) {
	s := runtime.NewScheme()
	if err := configv1.Install(s); err != nil {
		return nil, err
	}

	return fake.NewClientBuilder().WithScheme(s).WithObjects(obs...).Build(), nil
}

func TestCheckImageRegistryStatus(t *testing.T) {
	tests := []struct {
		name     string
		config   *configv1.Config
		expected bool
	}{
		{
			name: "test",
			config: &configv1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name: "notfound",
				},
				Spec:   configv1.ImageRegistrySpec{},
				Status: configv1.ImageRegistryStatus{},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		s := NewWebhook()
		s.kubeClient, _ = NewMock(test.config)
		actual, _ := s.CheckImageRegistryStatus(context.Background())
		if actual != test.expected {
			t.Error("failed")
		}
	}

}
