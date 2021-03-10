package user

// User creation logic:
// Red Hat associates (eg User IDs ending in @redhat.com) have special rules
// that must be followed:
// * If a User is a member of at least one of the three protected groups, the
// User creation object MUST be using the Red Hat SRE identity provider (idp),
// (eg identity.DefaultIdentityProvider)
// * If a User is a Red Hat associate (user ID ending @redhat.com), they MUST
// NOT be using the Red Hat SRE idp.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/userloader"

	// Only need the DefaultIdentityProvider
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/identity"
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	"k8s.io/api/admission/v1beta1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

const (
	WebhookName string = "user-validation"
	// redhatAssociateUserIDSuffix is used to restrict the creation of users with this
	// user ID suffix to membership in the redhatGroups (see below). Users
	redhatAssociateUserIDSuffix string = "@redhat.com"
	// Red Hat associates who are a member of at least one redhatGroups must use
	// this IDP, and users who use this IDP must be a member of at least one
	// redhatGroups.
	redHatIDP string = identity.DefaultIdentityProvider
	docString string = `Managed OpenShift customers and Red Hat associates have certain restrictions around logging in to the cluster. Red Hat SREs who manage managed clusters must use the %s identity provider, and not any other, so that their identity can be assured; Red Hat managed clusters SREs are members of at least one Red Hat managed group (%s). Other Red Hat associates who are not SREs may not use the %s identity provider to log into their clusters. Managed cluster customers may not use the %s identity provider, but may manage the users using other identity providers.`
)

var (
	log = logf.Log.WithName(WebhookName)
	// For Production use. Tests will set this to something else
	userLoaderBuilder = userloader.NewLoader
	// redhatGroups is a list of groups to which Red Hat associates must belong in
	// order to have a User provisioned for them (typically by the
	// openshift-authentication:oauth-openshift service account)
	redhatGroups = []string{"osd-devaccess", "osd-sre-admins", "layered-cs-sre-admins"}

	// adminGroups restrict who is authorized to create a User for a Red Hat associate
	adminGroups = []string{"osd-sre-admins", "osd-sre-cluster-admins", "system:serviceaccounts:openshift-authentication"}
	// kubeAdminUsernames are core Kubernetes users, not generally created by people
	// system:serviceaccount:openshift-authentication:oauth-openshift is omitted
	// from this intentionally so that the service account must abide by the Red
	// Hat associate check.
	// backplane-cluster-admin is a user we use in backplane to impersonate cluster-admin
	kubeAdminUsernames = []string{"kube:admin", "system:admin", "backplane-cluster-admin"}

	scope = admissionregv1.ClusterScope
	rules = []admissionregv1.RuleWithOperations{

		{
			Operations: []admissionregv1.OperationType{"UPDATE", "CREATE", "DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{"user.openshift.io"},
				APIVersions: []string{"*"},
				Resources:   []string{"users"},
				Scope:       &scope,
			},
		},
	}
)

// UserWebhook validates a User (user.openshift.io) change
type UserWebhook struct {
	mu sync.Mutex
	s  runtime.Scheme
	// Users is a list of @redhat.com (aka redhatAssociateUserIDSuffix) user IDs which are
	// allowed to have an account created. These are "fully qualified" to include
	// user ID and @redhat.com, populated by the loadUsers method.
	Users []string
}

type userRequest struct {
	Identities []string `json:"identities"` // what idp is being used for the User?
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

// ObjectSelector implements Webhook interface
func (s *UserWebhook) ObjectSelector() *metav1.LabelSelector { return nil }

func (s *UserWebhook) Doc() string {
	return fmt.Sprintf(docString, redHatIDP, redhatGroups, redHatIDP, redHatIDP)
}

// TimeoutSeconds implements Webhook interface
func (s *UserWebhook) TimeoutSeconds() int32 { return 2 }

// MatchPolicy implements Webhook interface
func (s *UserWebhook) MatchPolicy() admissionregv1.MatchPolicyType { return admissionregv1.Equivalent }

// Name implements Webhook interface
func (s *UserWebhook) Name() string { return WebhookName }

// FailurePolicy implements Webhook interface
func (s *UserWebhook) FailurePolicy() admissionregv1.FailurePolicyType { return admissionregv1.Ignore }

// Rules implements Webhook interface
func (s *UserWebhook) Rules() []admissionregv1.RuleWithOperations { return rules }

// GetURI implements Webhook interface
func (s *UserWebhook) GetURI() string { return "/user-validation" }

// SideEffects implements Webhook interface
func (s *UserWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// Validate is the incoming request even valid?
func (s *UserWebhook) Validate(req admissionctl.Request) bool {
	valid := true
	valid = valid && (req.UserInfo.Username != "")

	return valid
}

// isAuthorizedToEditRedHatUsers is a helper to consolidate logic. Returns true
// if the user making the webhook request is able to make edits to @redhat.com
// users.
func isAuthorizedToEditRedHatUsers(hookRequest admissionctl.Request) bool {
	for _, userGroup := range hookRequest.AdmissionRequest.UserInfo.Groups {
		if utils.SliceContains(userGroup, adminGroups) {
			return true
		}
	}
	return false
}

// isProtectedRedHatAssociate will indicate whether or not the subject of the webhook
// request is a Red Hat associate subject to additional protections (eg a member
// of the redhatGroups)
func (s *UserWebhook) isProtectedRedHatAssociate(userReq *userRequest) bool {
	return utils.SliceContains(userReq.Metadata.Name, s.Users)
}

// isRedHatAssociate will indicate whether or not the subject of the webhook
// request is ANY kind of Red Hat associate (eg, their user ID ends in the
// redhatAssociateUserIDSuffix)
func (s *UserWebhook) isRedHatAssociate(userReq *userRequest) bool {
	return strings.HasSuffix(userReq.Metadata.Name, redhatAssociateUserIDSuffix)
}

func (s *UserWebhook) isUsingRedHatIDP(userReq *userRequest) bool {
	for _, idp := range userReq.Identities {
		if strings.HasPrefix(idp+":", redHatIDP) {
			return true
		}
	}
	return false
}

// Authorized implements Webhook interface
func (s *UserWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *UserWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response
	var err error
	userReq := &userRequest{}

	// if we delete, then look to OldObject in the request.
	if request.Operation == v1beta1.Delete {
		err = json.Unmarshal(request.OldObject.Raw, userReq)
	} else {
		err = json.Unmarshal(request.Object.Raw, userReq)
	}
	if err != nil {
		ret = admissionctl.Errored(http.StatusBadRequest, err)
		return ret
	}

	// Admin kube admin users can do whatever they want
	if utils.SliceContains(request.AdmissionRequest.UserInfo.Username, kubeAdminUsernames) {
		log.Info("Admin users allowed", "subject", userReq.Metadata.Name)
		ret = admissionctl.Allowed("Admin users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Red Hat associates follow special rules about who can make changes and who
	// can have accounts
	if s.isRedHatAssociate(userReq) {
		// Load protected users from Kubernetes
		if err = s.loadUsers(); err != nil {
			fmt.Printf("Error loading users +%v\n", err.Error())
			log.Error(err, "Couldn't load any valid users! No @redhat.com associates may have an account!")
			admissionctl.Errored(http.StatusInternalServerError, err)
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		if !isAuthorizedToEditRedHatUsers(request) {
			log.Info("Not allowed work with Red Hat users", "subject", userReq.Metadata.Name, "requestor", request.AdmissionRequest.UserInfo.Username)
			ret = admissionctl.Denied("Not allowed to edit Red Hat Users")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		// We should be allowed to delete if they're not a member of the protected
		// group because that is a cleanup operation
		if request.AdmissionRequest.Operation == v1beta1.Delete {
			log.Info("Allowing a DELETE of a User", "userReq", userReq, "requestor", request.AdmissionRequest.UserInfo.Username)
			ret = admissionctl.Allowed("Allowed to delete a user")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		if s.isUsingRedHatIDP(userReq) {
			// Are they a member of redhatGroups? If so, good to go, otherwise not.
			if s.isProtectedRedHatAssociate(userReq) {
				log.Info("Red Hat Associates allowed to use SRE IDP", "subject", userReq.Metadata.Name, "IDP", redHatIDP)
				ret = admissionctl.Allowed("Red Hat associate allowed to use SRE IDP")
				ret.UID = request.AdmissionRequest.UID
				return ret
			}
			log.Info("Red Hat associates must be a member of redhatGroups to use SRE IDP", "subject", userReq.Metadata.Name, "requestor", request.AdmissionRequest.UserInfo.Username)
			ret = admissionctl.Denied("Red Hat associate must be a member of redhatGroups to use SRE IDP")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		if s.isProtectedRedHatAssociate(userReq) {
			// Protected users must use SRE IDP
			log.Info("Red Hat SREs must use SRE IDP", "subject", userReq.Metadata.Name, "requestor", request.AdmissionRequest.UserInfo.Username, "userReq.Identities", userReq.Identities)
			ret = admissionctl.Denied("Member of redhatGroups must use SRE IDP")
			ret.UID = request.AdmissionRequest.UID
			return ret
		}
		// Allowed
		log.Info("Red Hat Associates may use non-SRE IDP", "subject", userReq.Metadata.Name)
		ret = admissionctl.Allowed("Red Hat associate allowed to use non-SRE IDP")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}
	// Non-Red Hat associate
	ret = admissionctl.Allowed("Allowed by RBAC")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

func (s *UserWebhook) loadUsers() error {
	// load users, but do it a bit indirectly because it may (does) require itself
	// to be inside a Kubernetes cluster. When testing, we won't have that, and so
	// we'll need to mock that behaviour out.
	// We can plug in our own test-purpose user loader for that.
	ul, err := userLoaderBuilder()
	if err != nil {
		fmt.Printf("Error loading users: %s\n", err.Error())
		return err
	}
	userMap, err := ul.GetUsersFromGroups(redhatGroups...)
	if err != nil {
		return err
	}
	allUsers := make([]string, 0)
	// unique users
	hist := make(map[string]bool)
	for _, members := range userMap {
		// dedup
		for _, user := range members {
			if !hist[user] {
				allUsers = append(allUsers, user)
				hist[user] = true
			}
		}
	}
	s.Users = allUsers
	return nil
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
func (s *UserWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

// NewWebhook creates a new webhook
func NewWebhook() *UserWebhook {
	scheme := runtime.NewScheme()
	v1beta1.AddToScheme(scheme)
	corev1.AddToScheme(scheme)
	w := &UserWebhook{
		s: *scheme,
	}

	return w
}
