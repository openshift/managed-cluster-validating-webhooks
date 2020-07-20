package testutils

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"k8s.io/api/admission/v1beta1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Webhook interface
type Webhook interface {
	// HandleRequest handles an incoming webhook
	HandleRequest(http.ResponseWriter, *http.Request)
	// GetURI returns the URI for the webhook
	GetURI() string
	// Validate will validate the incoming request
	Validate(admissionctl.Request) bool
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
// 	obj := runtime.RawExtension{
//		Raw: []byte(rawObjString),
//	}
// where rawObjString is a literal JSON blob, eg:
// {
//  "metadata": {
//    "name": "namespace-name",
//    "uid": "request-userid",
//    "creationTimestamp": "2020-05-10T07:51:00Z"
//  },
//  "users": null
// }
func CreateFakeRequestJSON(uid string,
	gvk metav1.GroupVersionKind, gvr metav1.GroupVersionResource,
	operation v1beta1.Operation,
	username string, userGroups []string,
	obj, oldObject *runtime.RawExtension) ([]byte, error) {

	req := v1beta1.AdmissionReview{
		Request: &v1beta1.AdmissionRequest{
			UID:       types.UID(uid),
			Kind:      gvk,
			Resource:  gvr,
			Operation: operation,
			UserInfo: authenticationv1.UserInfo{
				Username: username,
				Groups:   userGroups,
			},
		},
	}
	switch operation {
	case v1beta1.Create:
		req.Request.Object = *obj
	case v1beta1.Update:
		// TODO (lisa): Update should have a different object for Object than for OldObject
		req.Request.Object = *obj
		if oldObject != nil {
			req.Request.OldObject = *oldObject
		} else {
			req.Request.OldObject = *obj
		}
	case v1beta1.Delete:
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
	operation v1beta1.Operation,
	username string, userGroups []string,
	obj, oldObject *runtime.RawExtension) (*http.Request, error) {
	req, err := CreateFakeRequestJSON(uid, gvk, gvr, operation, username, userGroups, obj, oldObject)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(req)
	httprequest := httptest.NewRequest("POST", uri, buf)
	httprequest.Header["Content-Type"] = []string{"application/json"}
	return httprequest, nil
}

// SendHTTPRequest will send the fake request to be handled by the Webhook
func SendHTTPRequest(req *http.Request, s Webhook) (*v1beta1.AdmissionResponse, error) {

	httpResponse := httptest.NewRecorder()
	s.HandleRequest(httpResponse, req)
	// at this popint, httpResponse should contain the data sent in response to the webhook query, which is the success/fail
	ret := &v1beta1.AdmissionReview{}
	err := json.Unmarshal(httpResponse.Body.Bytes(), ret)
	if err != nil {
		return nil, err
	}
	return ret.Response, nil
}
