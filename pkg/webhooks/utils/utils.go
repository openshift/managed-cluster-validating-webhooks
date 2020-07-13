package utils

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const validContentType string = "application/json"

var (
	admissionScheme = runtime.NewScheme()
	admissionCodecs = serializer.NewCodecFactory(admissionScheme)
)

func SliceContains(needle string, haystack []string) bool {
	for _, check := range haystack {
		if needle == check {
			return true
		}
	}
	return false
}

func ParseHTTPRequest(r *http.Request) (admissionctl.Request, admissionctl.Response, error) {
	var resp admissionctl.Response
	var req admissionctl.Request
	var err error
	var body []byte
	if r.Body != nil {
		if body, err = ioutil.ReadAll(r.Body); err != nil {
			resp = admissionctl.Errored(http.StatusBadRequest, err)
			return req, resp, err
		}
	} else {
		err := errors.New("request body is nil")
		resp = admissionctl.Errored(http.StatusBadRequest, err)
		return req, resp, err
	}
	if len(body) == 0 {
		err := errors.New("request body is empty")
		resp = admissionctl.Errored(http.StatusBadRequest, err)
		return req, resp, err
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != validContentType {
		err := fmt.Errorf("contentType=%s, expected application/json", contentType)
		resp = admissionctl.Errored(http.StatusBadRequest, err)
		return req, resp, err
	}
	ar := v1beta1.AdmissionReview{}
	if _, _, err := admissionCodecs.UniversalDeserializer().Decode(body, nil, &ar); err != nil {
		resp = admissionctl.Errored(http.StatusBadRequest, err)
		return req, resp, err
	}

	// Copy for tracking
	if ar.Request == nil {
		err = fmt.Errorf("No request in request body")
		resp = admissionctl.Errored(http.StatusBadRequest, err)
		return req, resp, err
	}
	resp.UID = ar.Request.UID
	req = admissionctl.Request{
		AdmissionRequest: *ar.Request,
	}
	return req, resp, nil
}

func init() {
	utilruntime.Must(v1beta1.AddToScheme(admissionScheme))
}
