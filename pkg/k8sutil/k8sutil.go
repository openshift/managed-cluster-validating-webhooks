package k8sutil

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type RunModeType string

const (
	LocalRunMode   RunModeType = "local"
	ClusterRunMode RunModeType = "cluster"

	OperatorNameEnvVar = "OPERATOR_NAME"
)

var (
	log = logf.Log.WithName("k8sutil")

	ForceRunModeEnv = "OSDK_FORCE_RUN_MODE"
	ErrNoNamespace  = fmt.Errorf("namespace not found for current environment")
	ErrRunLocal     = fmt.Errorf("operator run mode forced to local")
)

func buildConfig(kubeconfig string) (*rest.Config, error) {
	// Try loading KUBECONFIG env var.  If not set fallback on InClusterConfig

	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// KubeClient creates a new kubeclient that interacts with the Kube api with the service account secrets
func KubeClient(s *runtime.Scheme) (client.Client, error) {
	// Try loading KUBECONFIG env var.  Else falls back on in-cluster config
	config, err := buildConfig(os.Getenv("KUBECONFIG"))
	if err != nil {
		return nil, err
	}

	c, err := client.New(config, client.Options{
		Scheme: s,
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func isRunModeLocal() bool {
	return os.Getenv(ForceRunModeEnv) == string(LocalRunMode)
}

// GetOperatorNamespace returns the namespace the operator should be running in.
func GetOperatorNamespace() (string, error) {
	if isRunModeLocal() {
		return "", ErrRunLocal
	}
	nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNoNamespace
		}
		return "", err
	}
	ns := strings.TrimSpace(string(nsBytes))
	log.V(1).Info("Found namespace", "Namespace", ns)
	return ns, nil
}

// GetOperatorName return the operator name
func GetOperatorName() (string, error) {
	operatorName, found := os.LookupEnv(OperatorNameEnvVar)
	if !found {
		return "", fmt.Errorf("%s must be set", OperatorNameEnvVar)
	}
	if len(operatorName) == 0 {
		return "", fmt.Errorf("%s must not be empty", OperatorNameEnvVar)
	}
	return operatorName, nil
}
