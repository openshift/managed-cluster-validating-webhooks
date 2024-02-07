package localmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	MetricNodeWebhookBlockedReqeust = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "managed_webhook_node_blocked_request",
		Help: "Report how many times the managed node webhook has blocked requests",
	}, []string{"user"})

	MetricsList = []prometheus.Collector{
		MetricNodeWebhookBlockedReqeust,
	}
)

func IncrementNodeWebhookBlockedRequest(user string) {
	MetricNodeWebhookBlockedReqeust.With(prometheus.Labels{"user": user}).Inc()
}
