package service

import (
	"reflect"
	"testing"

	"gomodules.xyz/jsonpatch/v2"
)

const patchPath string = "/metadata/annotations/service.beta.kubernetes.io~1aws-load-balancer-additional-resource-tags"

var addJSONPatchOp jsonpatch.Operation = jsonpatch.NewOperation("add",
	patchPath,
	"red-hat-managed=true",
)

func Test_buildPatch(t *testing.T) {
	type args struct {
		serviceAnnotations map[string]string
	}
	tests := []struct {
		name string
		args args
		want jsonpatch.JsonPatchOperation
	}{
		{
			name: "no existing annotations",
			args: args{
				serviceAnnotations: map[string]string{},
			},
			want: addJSONPatchOp,
		},
		{
			name: "irrelevant existing annotations",
			args: args{
				serviceAnnotations: map[string]string{
					"foo": "bar",
					"machineconfiguration.openshift.io/controlPlaneTopology": "HighlyAvailable",
					"k8s.ovn.org/host-cidrs":                                 "[\"10.0.0.107/24\"]",
				},
			},
			want: addJSONPatchOp,
		},
		{
			name: "irrelevant existing resource tags",
			args: args{
				serviceAnnotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "Foo=Bar,ABC=123",
				},
			},
			want: jsonpatch.NewOperation("replace",
				patchPath,
				"red-hat-managed=true,Foo=Bar,ABC=123",
			),
		},
		{
			name: "relevant existing resource tags",
			args: args{
				serviceAnnotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "Foo=Bar,red-hat-managed=foobar",
				},
			},
			want: jsonpatch.NewOperation("replace",
				patchPath,
				"red-hat-managed=true,Foo=Bar",
			),
		},
		{
			name: "multiple relevant existing resource tags",
			args: args{
				serviceAnnotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "red-hat-managed=false,Foo=Bar,red-hat-managed=foobar",
				},
			},
			want: jsonpatch.NewOperation("replace",
				patchPath,
				"red-hat-managed=true,Foo=Bar",
			),
		},
		{
			name: "correct existing tags",
			args: args{
				serviceAnnotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "red-hat-managed=true,Foo=Bar,ABC=123",
				},
			},
			// Ideally, this never happens because the calling function won't try to build a
			// Patched() response if hasRedHatManagedTag() == true. If this does happen though,
			// we should return a replace operation that's effectively a no-op
			want: jsonpatch.NewOperation("replace",
				patchPath,
				"red-hat-managed=true,Foo=Bar,ABC=123",
			),
		},
		{
			name: "malformed existing resource tag",
			args: args{
				serviceAnnotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "#!&^",
				},
			},
			// We're not in the business of enforcing correct AWS tag syntax. If a resource tags
			// annotation is unacceptable before passing through this webhook, no need for us to
			// try to "save" it beyond inserting the required tag safely
			want: jsonpatch.NewOperation("replace",
				patchPath,
				"red-hat-managed=true,#!&^",
			),
		},
		{
			name: "multiple malformed existing resource tags",
			args: args{
				serviceAnnotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "!,,$,",
				},
			},
			// See above comment
			want: jsonpatch.NewOperation("replace",
				patchPath,
				"red-hat-managed=true,!,,$,",
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildPatch(tt.args.serviceAnnotations); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("buildPatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasRedHatManagedTag(t *testing.T) {
	type args struct {
		serviceAnnotations map[string]string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "happy path single tag",
			args: args{
				serviceAnnotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "red-hat-managed=true",
				},
			},
			want: true,
		},
		{
			name: "happy path with noise",
			args: args{
				serviceAnnotations: map[string]string{
					"foo": "bar",
					"machineconfiguration.openshift.io/controlPlaneTopology":                "HighlyAvailable",
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "red-hat-managed=true,Foo=Bar,ABC=123",
				},
			},
			want: true,
		},
		{
			name: "irrelevant annotations",
			args: args{
				serviceAnnotations: map[string]string{
					"foo": "bar",
					"machineconfiguration.openshift.io/controlPlaneTopology": "HighlyAvailable",
					"k8s.ovn.org/host-cidrs":                                 "[\"10.0.0.107/24\"]",
				},
			},
			want: false,
		},
		{
			name: "incorrect tag value",
			args: args{
				serviceAnnotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "red-hat-managed=false,Foo=Bar,ABC=123",
				},
			},
			want: false,
		},
		{
			name: "correct tag surrounded by garbage",
			args: args{
				serviceAnnotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": ",,red-hat-managed=true,#$%^",
				},
			},
			want: true,
		},
		{
			name: "empty annotations",
			args: args{
				serviceAnnotations: map[string]string{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRedHatManagedTag(tt.args.serviceAnnotations); got != tt.want {
				t.Errorf("hasRedHatManagedTag() = %v, want %v", got, tt.want)
			}
		})
	}
}
