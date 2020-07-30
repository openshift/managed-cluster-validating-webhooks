package userloader

import (
	"fmt"
	"testing"

	userv1 "github.com/openshift/api/user/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func createGroup(name string, userCount int) *userv1.Group {
	users := make([]string, userCount)
	for i := 0; i < userCount; i++ {
		users[i] = fmt.Sprintf("user-%d", i)
	}
	// return an abbreviated Group
	return &userv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Users: users,
	}
}

func NewTestLoader(objs []runtime.Object) *UserLoader {
	scheme := runtime.NewScheme()
	err := userv1.AddToScheme(scheme)
	if err != nil {
		panic(err)
	}
	c := fake.NewFakeClientWithScheme(scheme, objs...)
	return &UserLoader{
		scheme: *scheme,
		client: c,
	}
}

func TestNoGroups(t *testing.T) {
	// what happens if there's no groups loaded into the cluster?
	l := NewTestLoader([]runtime.Object{})
	users, err := l.GetUsersFromGroups("test")
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	if len(users) != 0 {
		t.Fatalf("Expected no users back, but got %d", len(users))
	}
}

func TestGroupWithNoUsers(t *testing.T) {
	// what happens if there's a group, but it has no users?
	group := createGroup("test", 0)
	l := NewTestLoader([]runtime.Object{group})
	users, err := l.GetUsersFromGroups("test")
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	if len(users) != 1 {
		t.Fatalf("Expected to have 1 group come back, but got %d", len(users))
	}
	if _, ok := users["test"]; !ok {
		t.Fatalf("Expected to get the test group back, but it doesn't appear to be a key in the map: %+v", users)
	}
	if len(users["test"]) != 0 {
		t.Fatalf("Expected no users back, but got %d", len(users["test"]))
	}
}

func TestWithGroup(t *testing.T) {
	group := createGroup("test", 2)
	l := NewTestLoader([]runtime.Object{group})
	users, err := l.GetUsersFromGroups("test")
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	if len(users) != 1 {
		t.Fatalf("Expected to get back 1 group, got %d", len(users))
	}
	if len(users["test"]) != 2 {
		t.Fatalf("Expected to get back 2 users from the group, got %d", len(users["test"]))
	}
}

func TestWith2Groups(t *testing.T) {
	group1 := createGroup("test", 2)
	group2 := createGroup("test2", 23)
	l := NewTestLoader([]runtime.Object{group1, group2})
	users, err := l.GetUsersFromGroups("test", "test2")
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	if len(users) != 2 {
		t.Fatalf("Expected to get back 2 group, got %d", len(users))
	}
	if len(users["test"]) != 2 {
		t.Fatalf("Expected to get back 2 users from test group, got %d", len(users["test"]))
	}
	if len(users["test2"]) != 23 {
		t.Fatalf("Expected to get back 23 users from test2 group, got %d", len(users["test2"]))
	}
}
