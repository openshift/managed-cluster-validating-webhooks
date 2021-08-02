package helpers

import (
	"encoding/json"
	"io"
	"net/http"

	admissionapi "k8s.io/api/admission/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var log = logf.Log.WithName("response_helper")

// SendResponse Send the AdmissionReview.
func SendResponse(w io.Writer, resp admissionctl.Response) {

	// Apply ownership annotation to allow for granular alerts for
	// manipulation of SREP owned webhooks.
	resp.AuditAnnotations = map[string]string{
		"owner": "srep-managed-webhook",
	}

	encoder := json.NewEncoder(w)
	responseAdmissionReview := admissionapi.AdmissionReview{
		Response: &resp.AdmissionResponse,
	}
	responseAdmissionReview.APIVersion = admissionapi.SchemeGroupVersion.String()
	responseAdmissionReview.Kind = "AdmissionReview"
	err := encoder.Encode(responseAdmissionReview)
	// TODO (lisa): handle this in a non-recursive way (why would the second one succeed)?
	if err != nil {
		log.Error(err, "Failed to encode Response", "response", resp)
		SendResponse(w, admissionctl.Errored(http.StatusInternalServerError, err))
	}
}
