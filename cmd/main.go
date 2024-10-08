package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/openshift/operator-custom-metrics/pkg/metrics"
	klog "k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openshift/managed-cluster-validating-webhooks/config"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/dispatcher"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/k8sutil"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/localmetrics"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
)

var log = logf.Log.WithName("handler")

var (
	listenAddress = flag.String("listen", "0.0.0.0", "listen address")
	listenPort    = flag.String("port", "5000", "port to listen on")
	metricsAddr   string

	useTLS  = flag.Bool("tls", false, "Use TLS? Must specify -tlskey, -tlscert, -cacert")
	tlsKey  = flag.String("tlskey", "", "TLS Key for TLS")
	tlsCert = flag.String("tlscert", "", "TLS Certificate")
	caCert  = flag.String("cacert", "", "CA Cert file")

	metricsPath = "/metrics"
	metricsPort = "8080"
)

func init() {
	// Allow export webhook var to share flag value...
	flag.BoolVar(&utils.TestHooks, "testhooks", false, "Test webhook URI uniqueness and quit?")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":"+metricsPort, "The address the metric endpoint binds to.")
	flag.Parse()
}

func main() {
	klog.SetOutput(os.Stdout)
	logf.SetLogger(klogr.New())

	if !utils.TestHooks {
		log.Info("HTTP server running at", "listen", net.JoinHostPort(*listenAddress, *listenPort))
	}
	dispatcher := dispatcher.NewDispatcher(webhooks.Webhooks)
	seen := make(map[string]bool)
	for name, hook := range webhooks.Webhooks {
		realHook := hook()
		if seen[realHook.GetURI()] {
			panic(fmt.Errorf("Duplicate webhook trying to listen on %s", realHook.GetURI()))
		}
		seen[name] = true
		if !utils.TestHooks {
			log.Info("Listening", "webhookName", name, "URI", realHook.GetURI())
		}
		http.HandleFunc(realHook.GetURI(), dispatcher.HandleRequest)
	}
	if utils.TestHooks {
		os.Exit(0)
	}

	// start metrics server
	metricsServer := metrics.NewBuilder(config.OperatorNamespace, fmt.Sprintf("%s-metrics", config.OperatorName)).
		WithPort(metricsPort).
		WithPath(metricsPath).
		WithServiceLabel(map[string]string{"app": "validation-webhook"}).
		WithCollectors(localmetrics.MetricsList).
		GetConfig()

	// get the namespace we're running in to confirm if running in a cluster
	if _, err := k8sutil.GetOperatorNamespace(); err != nil {
		if errors.Is(err, k8sutil.ErrRunLocal) {
			log.Info("Skipping metrics server creation; not running in a cluster.")
		} else {
			log.Error(err, "Failed to get operator namespace")
		}
	} else {
		if err := metrics.ConfigureMetrics(context.TODO(), *metricsServer); err != nil {
			log.Error(err, "Failed to configure metrics")
		} else {
			log.Info("Successfully configured metrics")
		}
	}

	server := &http.Server{
		Addr: net.JoinHostPort(*listenAddress, *listenPort),
	}
	if *useTLS {
		cafile, err := os.ReadFile(*caCert)
		if err != nil {
			log.Error(err, "Couldn't read CA cert file")
			os.Exit(1)
		}
		certpool := x509.NewCertPool()
		certpool.AppendCertsFromPEM(cafile)

		server.TLSConfig = &tls.Config{
			RootCAs: certpool,
		}
		log.Error(server.ListenAndServeTLS(*tlsCert, *tlsKey), "Error serving TLS")
	} else {
		log.Error(server.ListenAndServe(), "Error serving non-TLS connection")
	}
}
