package userloader

import (
	"context"
	"sync"

	userv1 "github.com/openshift/api/user/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Loader will be used to get users from groups
type Loader interface {
	GetUsersFromGroups(...string) (map[string][]string, error)
}

// UserLoader implements Loader, to fetch users from a set of Kubernetes groups
type UserLoader struct {
	scheme runtime.Scheme
	client client.Client
	mu     sync.Mutex
}

// NewLoader returns a new Loader in order to read group membership
func NewLoader() (Loader, error) {
	scheme := runtime.NewScheme()
	if err := userv1.AddToScheme(scheme); err != nil {
		return &UserLoader{}, err
	}
	r, err := rest.InClusterConfig()
	if err != nil {
		return &UserLoader{}, err
	}
	cl, err := client.New(r, client.Options{Scheme: scheme})
	if err != nil {
		return &UserLoader{}, err
	}
	l := &UserLoader{
		scheme: *scheme,
		client: cl,
	}
	return l, nil
}

// GetUsersFromGroups implements Loader by returning a map of group name ->
// members to that group. If a group does not exist, there will not be a key in
// the resultant map
func (l *UserLoader) GetUsersFromGroups(groupNames ...string) (map[string][]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ret := make(map[string][]string)
	for _, groupName := range groupNames {
		group := userv1.Group{}
		err := l.client.Get(context.TODO(), types.NamespacedName{Namespace: "", Name: groupName}, &group)
		if err != nil {
			if errors.IsNotFound(err) {
				// this one is okay to skip because the returned map will simply lack
				// the key for this non-existant groupName to handle the not found
				// error.
				continue
			}
			return ret, err
		}
		ret[groupName] = []string(group.Users)
	}
	return ret, nil
}
