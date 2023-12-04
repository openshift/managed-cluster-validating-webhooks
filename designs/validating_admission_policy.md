# Deprecate Validating Webhooks and Migrate to ValidatingAdmissionPolicy

Author: @mjlshen

Last Updated: 12/04/2023

## Summary

This is a proposal to deprecate this repo and migrate to [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy)
which is in beta in Kubernetes v1.28 and being pulled into OCP via [API-1609](https://issues.redhat.com/browse/API-1609)
as a `CustomNoUpgrade` feature set in 4.14 and as a `TechPreviewNoUpgrade` feature set in 4.15. This proposal will build
upon [KEP-3488: CEL for Admission Control](https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/3488-cel-admission-control/README.md)
and focus on the specific benefits it can provide to OSD/ROSA and how this repo can be safely deprecated during the
migration to `ValidatingAdmissionPolicy`.

## Motivation

[Common Expression Language (CEL)](https://kubernetes.io/docs/reference/using-api/cel/) has been gaining traction as a
way to declaratively [validate CustomResourceDefinitions (CRDs)](https://kubernetes.io/blog/2022/09/23/crd-validation-rules-beta/) and is recently being pulled in to replace the need for
most use-cases for validating admission webhooks via `ValidatingAdmissionPolicy`.

This proposal will allow us to:

- Continue performing admission control with parity to existing `ValidatingWebhookConfigurations`
- Allow safer experimentation with "fail closed" admission control
  - Leverages [Common Expression Language (CEL)](https://kubernetes.io/docs/reference/using-api/cel/) which uses syntax familiar to Go developers
  - Type-checking was done previously in Go and [remains with CEL](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#type-checking)
  - Errors with the managed-cluster-validating-webhooks workload itself can have enormous impact on a cluster in "fail closed" admission control
    - `ValidatingAdmissionPolicy` allows the scope of impact to be restricted to a single policy and removes a dependency on networking to the validating webhook working
- Stop maintaining and deploying a custom workload
  - It has been difficult to onboard new developers and safely add new webhooks
  - Customers would appreciate having one less thing that consumes resources/needs to run on their clusters
- Allow OSD/ROSA guardrails to be more transparent to users
- Align with upstream recommendations [KEP-3488](https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/3488-cel-admission-control/README.md#motivation)

## Relevant Links

- [SD-ADR-0184: Migrating ValidatingWebhooks to ValidatingAdmissionPolicy](https://docs.google.com/document/d/1bgUr2CE6Al68uIU7bUDXszPiTefRQe3nSHoR3_rIwm4)
- [ValidatingAdmissionPolicy Documentation](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy)
- [API-1609](https://issues.redhat.com/browse/API-1609) Validating Admission Policies
- [KEP-3488: CEL for Admission Control](https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/3488-cel-admission-control/README.md)
- [KEP-2876: CRD Validation Expression Language](https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/2876-crd-validation-expression-language)

## Goals

- Continue to perform validating admission control, including all existing checks
- Replace validating webhooks with `ValidatingAdmissionPolicy` when it becomes available
- Allow OSD/ROSA to stop deploying validating webhook deployments/pods
- Provide an SLO around policy enforcement

## Non-Goals/Future Work

- Fill an existing gap for conversion/mutating webhooks. [KEP-3962: MutatingAdmissionPolicies](https://github.com/kubernetes/enhancements/pull/3963) is WIP and we can evaluate that later if it is promising 

## Proposal

- We begin to convert existing `ValidatingWebhookConfigurations` into `ValidatingAdmissionPolicies`, but do not deploy them yet.
- Restrict the [MCVW SelectorSyncSet](https://github.com/openshift/managed-cluster-validating-webhooks/blob/master/build/selectorsyncset.yaml) so that it will not install on 4.16+ (or whenever ValidatingAdmissionPolicy is GA in OCP)
- Move platform-wide `ValidatingAdmissionPolicies` to [managed-cluster-config](https://github.com/openshift/managed-cluster-config) and deploy them to clusters where `ValidatingAdmissionPolicies` are available

### Service Level Objectives

`apiserver_validating_admission_policy_check_duration_seconds`
Validation admission latency for individual validation expressions in seconds, labeled by policy and further including binding, state and enforcement action taken.

- Validation admission latency: 95% of checks occur within 2 seconds per binding per day
  - 2 seconds is a commonly used webhook timeout duration in the current repo, so we want to make sure that we are not worse than current performance (the theory is that the performance should be better)

`apiserver_validating_admission_policy_check_total`
Validation admission policy check total, labeled by policy and further identified by binding, enforcement action taken, and state.

- Validation admission enforcement: When writing new policies, fleet-wide, 95% of enforcement actions are not `Deny` per week
  - New policies should first use the `Warn` enforcement action and then we can assess whether the policy is safe to move to `Deny` enforcement immediately or whether the webhook needs to be changed, more customer communication is needed, or something else.

## User Stories

### Cluster-wide ValidatingWebhook: TechPreviewNoUpgrade

[TechPreviewNoUpgrade](https://github.com/openshift/managed-cluster-validating-webhooks/tree/12c076fc38667b717f10ad478a3cb5467bc8e06f/pkg/webhooks/techpreviewnoupgrade) is a relatively straightforward `ValidatingWebhookConfiguration`
that simply denies an action without exception.

```yaml
---
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingAdmissionPolicy
metadata:
  name: "techpreviewnoupgrade-validation.managed.openshift.io"
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["config.openshift.io"]
        apiVersions: ['*']
        operations: ["CREATE", "UPDATE"]
        resources: ["featuregates"]
  validations:
    - expression: "object.spec.featureSet != 'TechPreviewNoUpgrade'"
      message: "Managed OpenShift Customers may not enable the TechPreviewNoUpgrade feature set because it prevents the ability to perform y-stream upgrades"
      reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "techpreviewnoupgrade-validation.managed.openshift.io"
spec:
  policyName: "techpreviewnoupgrade-validation.managed.openshift.io"
  validationActions: ["Deny"]
```

## Managed Namespaces ValidatingWebhook: ClusterRoleBinding

The [ClusterRoleBinding](https://github.com/openshift/managed-cluster-validating-webhooks/tree/12c076fc38667b717f10ad478a3cb5467bc8e06f/pkg/webhooks/clusterrolebinding)
webhook is a bit more involved. It blocks the deletion of certain `ClusterRoleBindings` depending on the user requesting the deletion and the namespaces
of `ServiceAccounts` using the `ClusterRoleBinding`. This webhook is representative of webhooks that prevent actions against certain "managed"
namespaces and `ValidatingAdmissionPolicy` allows for ample flexibility to cover this use-case.

Of note, this example leverages a new CRD we would have to define: `protectednamespaces.rules.managed.openshift.io`, though
we could also place the list of namespaces inside the `ValidatingAdmissionPolicy` CR as a variable if we preferred.

```yaml
---
apiVersion: rules.managed.openshift.io/v1alpha1
kind: ProtectedNamespaces
metadata:
  name: "rosa-clusterrolebindings"
managedNamespaces:
  # https://github.com/openshift/managed-cluster-config/blob/bd9a34289d40bb084918a9eedfe20e568ae3a312/deploy/osd-managed-resources/managed-namespaces.ConfigMap.yaml
  - dedicated-admin
  - openshift-addon-operator
---
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingAdmissionPolicy
metadata:
  name: "clusterrolebinding-validation.managed.openshift.io"
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["rbac.authorization.k8s.io"]
        apiVersions: ["v1"]
        operations: ["DELETE"]
        resources: ["clusterrolebindings"]
  matchConditions:
    - name: 'exclude-kube-users'
      expression: "!request.userInfo.Username.startsWith('kube:')"
    - name: 'exclude-authenticated-system-users'
      expression: "!(request.userInfo.Username != 'system:unauthenticated && request.userInfo.Username.startsWith('system:'))"
  paramKind:
    apiVersion: "rules.managed.openshift.io/v1alpha1"
    kind: ProtectedNamespaces
  variables:
    - name: isAllowedUserGroup
      expression: "request.userInfo.Username == 'backplane-cluster-admin' || request.userInfo.groups.filter(group, group == 'system:serviceaccounts:openshift-backplane-srep')"
    - name: isAllowedNamespace
      expression: "!object.subjects.filter(s, s.kind == 'ServiceAccount').exists(s, params.managedNamespaces.exists(ns, ns == s.namespace))"
  validations:
    - expression: "!(variables.isAllowedNamespace || variables.isAllowedUserGroup)"
      messageExpression: "'Managed OpenShift Customers may not delete the cluster role bindings under the managed namespaces: ' + params.managedNamespaces"
      reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "clusterrolebinding-validation.managed.openshift.io"
spec:
  paramRef:
    name: "rosa-clusterrolebindings"
  policyName: "clusterrolebinding-validation.managed.openshift.io"
  validationActions: ["Deny"]
```

## Risks and Mitigations

- Customers can edit `ValidatingAdmissionPolicy` custom resources
  - We can block this with another `ValidatingAdmissionPolicy`
- Complexity from lines of Go code will initially be shifted to complexity around learning Common Expression Language (CEL)
  - We will be using CEL more and more regardless, via validating our own custom CRDs and there are existing [docs with examples](https://kubernetes.io/docs/reference/using-api/cel)
  - There are built-in metrics to ensure that `ValidatingAdmissionPolicies` that we author are doing as we expect

## Alternatives

- Continue maintaining this codebase
- Migrate to a third-party validating admission control system, such as OPA Gatekeeper or Kyverno
  - Notably ARO is currently using [OPA Gatekeeper](https://github.com/Azure/ARO-RP/blob/4a1ea4074e03b4e40b7f7ea94d885904f3ede1c0/pkg/operator/controllers/guardrails/policies/README.md)
