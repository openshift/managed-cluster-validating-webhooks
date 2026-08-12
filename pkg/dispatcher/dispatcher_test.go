package dispatcher

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks"
)

type fakeWebhook struct{}

func (f *fakeWebhook) Authorized(_ admissionctl.Request) admissionctl.Response {
	return admissionctl.Allowed("ok")
}
func (f *fakeWebhook) GetURI() string                                  { return "/test-hook" }
func (f *fakeWebhook) Validate(_ admissionctl.Request) bool            { return true }
func (f *fakeWebhook) Name() string                                    { return "test-validation" }
func (f *fakeWebhook) FailurePolicy() admissionregv1.FailurePolicyType { return admissionregv1.Ignore }
func (f *fakeWebhook) MatchPolicy() admissionregv1.MatchPolicyType     { return admissionregv1.Equivalent }
func (f *fakeWebhook) Rules() []admissionregv1.RuleWithOperations      { return nil }
func (f *fakeWebhook) ObjectSelector() *metav1.LabelSelector           { return nil }
func (f *fakeWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}
func (f *fakeWebhook) TimeoutSeconds() int32                      { return 2 }
func (f *fakeWebhook) Doc() string                                { return "" }
func (f *fakeWebhook) SyncSetLabelSelector() metav1.LabelSelector { return metav1.LabelSelector{} }
func (f *fakeWebhook) ClassicEnabled() bool                       { return true }
func (f *fakeWebhook) HypershiftEnabled() bool                    { return false }

func newTestDispatcher() *Dispatcher {
	hooks := webhooks.RegisteredWebhooks{
		"test-validation": func() webhooks.Webhook { return &fakeWebhook{} },
	}
	return NewDispatcher(hooks)
}

func validAdmissionReviewBody() []byte {
	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: types.UID("test-uid"),
			Kind: metav1.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Namespace",
			},
			Resource: metav1.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "namespaces",
			},
			Operation: admissionv1.Create,
		},
	}
	b, _ := json.Marshal(ar)
	return b
}

func TestHandleRequest_OversizedBody(t *testing.T) {
	d := newTestDispatcher()

	oversized := make([]byte, maxBodyBytes+1)
	for i := range oversized {
		oversized[i] = 'A'
	}

	req := httptest.NewRequest("POST", "/test-hook", bytes.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.HandleRequest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d for oversized body, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandleRequest_ValidRequest(t *testing.T) {
	d := newTestDispatcher()

	body := validAdmissionReviewBody()
	req := httptest.NewRequest("POST", "/test-hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.HandleRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &review); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if !review.Response.Allowed {
		t.Error("expected request to be allowed")
	}
}

func TestHandleRequest_UnknownURI(t *testing.T) {
	d := newTestDispatcher()

	req := httptest.NewRequest("POST", "/unknown-hook", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.HandleRequest(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d for unknown URI, got %d", http.StatusNotFound, w.Code)
	}
}

func TestHandleRequest_ConcurrentRequests(t *testing.T) {
	d := newTestDispatcher()
	body := validAdmissionReviewBody()

	const concurrency = 20
	var wg sync.WaitGroup
	wg.Add(concurrency)
	errors := make(chan string, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/test-hook", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			d.HandleRequest(w, req)
			if w.Code != http.StatusOK {
				errors <- "expected 200"
			}
		}()
	}

	wg.Wait()
	close(errors)
	for e := range errors {
		t.Error(e)
	}
}
