package dispatcher

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	responsehelper "github.com/openshift/managed-cluster-validating-webhooks/pkg/helpers"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
)

var log = logf.Log.WithName("dispatcher")

// Dispatcher struct
type Dispatcher struct {
	hooks *map[string]webhooks.WebhookFactory // uri -> hookfactory
	mu    sync.Mutex
}

// NewDispatcher new dispatcher
func NewDispatcher(hooks webhooks.RegisteredWebhooks) *Dispatcher {
	hookMap := make(map[string]webhooks.WebhookFactory)
	for _, hook := range hooks {
		hookMap[hook().GetURI()] = hook
	}
	return &Dispatcher{
		hooks: &hookMap,
	}
}

// HandleRequest http request
// HTTP status code usage: When the request body is correctly parsed into a
// request (utils.ParseHTTPRequest) then we should always send 200 OK and use
// the response body (response.status.code) to indicate a problem. When instead
// there's a problem with the HTTP request itself (404, an inability to parse a
// request, or some internal problem) it is appropriate to use the HTTP status
// code to communicate.
func (d *Dispatcher) HandleRequest(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	log.Info("Handling request", "request", r.RequestURI)
	url, err := url.Parse(r.RequestURI)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Error(err, "Couldn't parse request %s", r.RequestURI)
		responsehelper.SendResponse(w, admissionctl.Errored(http.StatusBadRequest, err))
		return
	}

	// is it one of ours?
	if hook, ok := (*d.hooks)[url.Path]; ok {
		// it's one of ours, so let's attempt to parse the request
		request, _, err := utils.ParseHTTPRequest(r)
		// Problem even parsing an AdmissionReview, so use HTTP status code
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Error(err, "Error parsing HTTP Request Body")
			responsehelper.SendResponse(w, admissionctl.Errored(http.StatusBadRequest, err))
			return
		}
		// Valid AdmissionReview, but we can't do anything with it because we do not
		// think the request inside is valid.
		if !hook().Validate(request) {
			err = fmt.Errorf("not a valid webhook request")
			log.Error(err, "Error validaing HTTP Request Body")
			responsehelper.SendResponse(w,
				admissionctl.Errored(http.StatusBadRequest, err))
			return
		}

		// Dispatch
		responsehelper.SendResponse(w, hook().Authorized(request))
		return
	}
	log.Info("Request is not for a registered webhook.", "known_hooks", *d.hooks, "parsed_url", url, "lookup", (*d.hooks)[url.Path])
	// Not a registered hook
	// Note: This segment is not likely to be reached because there will not be
	// any URI registered (handler set up) for an URI that would trigger this.
	w.WriteHeader(404)
	responsehelper.SendResponse(w,
		admissionctl.Errored(http.StatusBadRequest,
			fmt.Errorf("request is not for a registered webhook")))
}
