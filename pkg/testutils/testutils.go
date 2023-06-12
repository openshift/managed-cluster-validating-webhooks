package testutils

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	responsehelper "github.com/openshift/managed-cluster-validating-webhooks/pkg/helpers"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
)

// Webhook interface
type Webhook interface {
	// Authorized will determine if the request is allowed
	Authorized(request admissionctl.Request) admissionctl.Response
}

// CanCanNot helper to make English a bit nicer
func CanCanNot(b bool) string {
	if b {
		return "can"
	}
	return "can not"
}

// CreateFakeRequestJSON will render the []byte slice needed for the (fake) HTTP request.
// Inputs into this are the request UID, which GVK and GVR are being gated by this webhook,
// User information (username and groups), what kind of operation is being gated by this webhook
// and finally the runtime.RawExtension representation of the request's Object or OldObject
// The Object/OldObject is automatically inferred by the operation; delete operations will force OldObject
// To create the RawExtension:
//
//	obj := runtime.RawExtension{
//		Raw: []byte(rawObjString),
//	}
//
// where rawObjString is a literal JSON blob, eg:
//
//	{
//	 "metadata": {
//	   "name": "namespace-name",
//	   "uid": "request-userid",
//	   "creationTimestamp": "2020-05-10T07:51:00Z"
//	 },
//	 "users": null
//	}
func CreateFakeRequestJSON(uid string,
	gvk metav1.GroupVersionKind, gvr metav1.GroupVersionResource,
	operation admissionv1.Operation,
	username string, userGroups []string, namespace string,
	obj, oldObject *runtime.RawExtension) ([]byte, error) {

	req := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:         types.UID(uid),
			Kind:        gvk,
			RequestKind: &gvk,
			Resource:    gvr,
			Operation:   operation,
			Namespace:   namespace,
			UserInfo: authenticationv1.UserInfo{
				Username: username,
				Groups:   userGroups,
			},
		},
	}
	switch operation {
	case admissionv1.Create:
		req.Request.Object = *obj
	case admissionv1.Update:
		// TODO (lisa): Update should have a different object for Object than for OldObject
		req.Request.Object = *obj
		if oldObject != nil {
			req.Request.OldObject = *oldObject
		} else {
			req.Request.OldObject = *obj
		}
	case admissionv1.Delete:
		req.Request.OldObject = *obj
	}
	b, err := json.Marshal(req)
	if err != nil {
		return []byte{}, err
	}
	return b, nil
}

// CreateHTTPRequest takes all the information needed for an AdmissionReview.
// See also CreateFakeRequestJSON for more.
func CreateHTTPRequest(uri, uid string,
	gvk metav1.GroupVersionKind, gvr metav1.GroupVersionResource,
	operation admissionv1.Operation,
	username string, userGroups []string, namespace string,
	obj, oldObject *runtime.RawExtension) (*http.Request, error) {
	req, err := CreateFakeRequestJSON(uid, gvk, gvr, operation, username, userGroups, namespace, obj, oldObject)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(req)
	httprequest := httptest.NewRequest("POST", uri, buf)
	httprequest.Header["Content-Type"] = []string{"application/json"}
	return httprequest, nil
}

// SendHTTPRequest will send the fake request to be handled by the Webhook
func SendHTTPRequest(req *http.Request, s Webhook) (*admissionv1.AdmissionResponse, error) {
	httpResponse := httptest.NewRecorder()
	request, _, err := utils.ParseHTTPRequest(req)
	if err != nil {
		return nil, err
	}
	resp := s.Authorized(request)
	responsehelper.SendResponse(httpResponse, resp)
	// at this popint, httpResponse should contain the data sent in response to the webhook query, which is the success/fail
	ret := &admissionv1.AdmissionReview{}
	err = json.Unmarshal(httpResponse.Body.Bytes(), ret)
	if err != nil {
		return nil, err
	}
	return ret.Response, nil
}
