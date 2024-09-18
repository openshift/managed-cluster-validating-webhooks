package utils

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	validContentType string = "application/json"
	// PrivilegedServiceAccountGroups is a regex string of serviceaccounts that our webhooks should commonly allow to
	// perform restricted actions.
	// Centralized osde2e tests have a serviceaccount like "system:serviceaccounts:osde2e-abcde"
	// Decentralized osde2e tests have a serviceaccount like "system:serviceaccounts:osde2e-h-abcde"
	PrivilegedServiceAccountGroups string = `^system:serviceaccounts:(kube-.*|openshift|openshift-.*|default|redhat-.*|osde2e-(h-)?[a-z0-9]{5})`
)

var (
	// Allows sharing of testhooks 'make test' flag value used by main to test "webhook URI uniqueness"
	TestHooks       bool
	admissionScheme = runtime.NewScheme()
	admissionCodecs = serializer.NewCodecFactory(admissionScheme)
)

func RequestMatchesGroupKind(req admissionctl.Request, kind, group string) bool {
	return req.Kind.Kind == kind && req.Kind.Group == group
}

func DefaultLabelSelector() metav1.LabelSelector {
	return metav1.LabelSelector{
		MatchLabels: map[string]string{
			"api.openshift.com/managed": "true",
		},
	}
}

func IsProtectedByResourceName(name string) bool {
	protectedNames := []string{
		"alertmanagerconfigs.monitoring.coreos.com",
		"alertmanagers.monitoring.coreos.com",
		"prometheuses.monitoring.coreos.com",
		"thanosrulers.monitoring.coreos.com",
		"podmonitors.monitoring.coreos.com",
		"probes.monitoring.coreos.com",
		"prometheusrules.monitoring.coreos.com",
		"servicemonitors.monitoring.coreos.com",
		"prometheusagents.monitoring.coreos.com",
		"scrapeconfigs.monitoring.coreos.com",
	}
	return slices.Contains(protectedNames, name)
}

func RegexSliceContains(needle string, haystack []string) bool {
	for _, check := range haystack {
		checkRe := regexp.MustCompile(check)
		if checkRe.Match([]byte(needle)) {
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
		if body, err = io.ReadAll(r.Body); err != nil {
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
	ar := admissionv1.AdmissionReview{}
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

// WebhookResponse assembles an allowed or denied admission response with the same UID as the provided request.
// The reason for allowed admission responses is not shown to the end user and is commonly empty string: ""
func WebhookResponse(request admissionctl.Request, allowed bool, reason string) admissionctl.Response {
	resp := admissionctl.ValidationResponse(allowed, reason)
	resp.UID = request.UID
	return resp
}

func init() {
	utilruntime.Must(admissionv1.AddToScheme(admissionScheme))
}
