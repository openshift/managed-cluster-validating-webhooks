# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Go-based Kubernetes validating/mutating webhooks framework for OpenShift Dedicated (OSD) and ROSA managed clusters. Implements 25+ webhooks that enforce security policies and operational constraints.

**Primary Purpose**: Prevent managed cluster users from modifying protected namespaces, resources, and configurations while allowing authorized SRE and system operations.

## Key Commands

```bash
# Development
make test              # Run tests and webhook validation
make build             # Build binary
make vet               # Run linter
make coverage          # Generate coverage report

# Resource Generation
make syncset           # Generate SelectorSyncSet YAML for Classic → build/selectorsyncset.yaml
make package           # Generate Package Operator for HyperShift → build/package/*
make docs              # Generate webhook documentation → docs/webhooks.json
make generate          # Update namespace lists from ConfigMaps → pkg/config/namespaces.go

# Container Images
make build-image       # Build container image for Classic
make build-package-image # Build PKO package for HyperShift
make build-base        # Build both images
make push-base         # Push both images

# Local Testing - See README.md "Local Live Testing" section for full guide
make test-webhook WEBHOOK=namespace
go test ./pkg/webhooks/namespace/... -v
```

## Architecture

### Framework Design
- **Interface-Based**: All webhooks implement `Webhook` interface in [pkg/webhooks/register.go](pkg/webhooks/register.go)
- **Factory Pattern**: Webhooks register via `init()` in `add_*.go` files
- **Centralized Dispatcher**: Single HTTP server routes to webhooks by URI
- **Plugin System**: Self-contained modules in `pkg/webhooks/*/`

### Deployment Models
- **OSD/ROSA Classic**: DaemonSet via SelectorSyncSet to master nodes
- **ROSA HyperShift**: Package Operator (PKO) to hosted control plane
- **Control**: Each webhook has `ClassicEnabled()` and `HypershiftEnabled()` methods

### Core Components
- [cmd/main.go](cmd/main.go) - HTTP server with TLS, metrics, webhook routing
- [pkg/dispatcher/](pkg/dispatcher/) - Thread-safe request routing
- [pkg/webhooks/](pkg/webhooks/) - 25+ webhook implementations
- [pkg/config/namespaces.go](pkg/config/namespaces.go) - Protected namespaces (auto-generated)
- [build/resources.go](build/resources.go) - Dynamic resource generation

### Current Webhooks (25)
See `ls pkg/webhooks/` for full list. Key ones:
- `namespace` - Core namespace protection
- `regularuser` - Regular user validation  
- `pod` - Privileged pod operations
- `service` - AWS ELB tagging (mutating)
- `scc` - SecurityContextConstraints protection
- `ingresscontroller` - Ingress protection

## Adding New Webhooks

See [README.md](README.md) sections "Adding New Webhooks" and "Development" for detailed guide.

**Quick Steps**:
1. Create `pkg/webhooks/mywebhook/mywebhook.go` implementing `Webhook` interface
2. Create `pkg/webhooks/add_mywebhook.go` registration file
3. Write tests in `mywebhook_test.go` using `pkg/testutils` helpers
4. Run `make syncset && make package && make docs && make test`

**Key Interface Methods**:
- `Name()` - Must be unique, end with `-validation` or `-mutation`
- `GetURI()` - Must be unique path
- `Authorized()` - Core webhook logic and authorization
- `Validate()` - Request structure validation
- `Rules()` - K8s admission rules (resources, operations, API groups)
- `ClassicEnabled()` / `HypershiftEnabled()` - Deployment targets
- See [pkg/webhooks/register.go](pkg/webhooks/register.go) for full interface

**Naming Convention**: Build system auto-detects webhook type by name suffix:
- `-validation` → ValidatingWebhookConfiguration
- `-mutation` → MutatingWebhookConfiguration

## Authorization Patterns

Common patterns in `Authorized()` method:

```go
// Pattern 1: Allow cluster admins and SRE, deny regular users
if utils.IsClusterAdmin(request) || utils.IsInSREGroup(request) {
    return admissionctl.Allowed("Authorized")
}
return admissionctl.Denied("Regular users cannot modify this resource")

// Pattern 2: Check privileged service accounts
if utils.IsPrivilegedServiceAccount(request) {
    return admissionctl.Allowed("Privileged service account")
}

// Pattern 3: Namespace pattern checks
if strings.HasPrefix(namespace, "openshift-") && !utils.IsInSREGroup(request) {
    return admissionctl.Denied("Cannot modify openshift-* namespace")
}
```

**Authorization Hierarchy** (highest to lowest privilege):
1. Cluster Admins - `utils.IsClusterAdmin()` - `kube:admin`, `system:admin`, `backplane-cluster-admin`
2. SRE Groups - `utils.IsInSREGroup()` - `system:serviceaccounts:openshift-backplane-srep`
3. Privileged ServiceAccounts - `utils.IsPrivilegedServiceAccount()` - System service accounts
4. Layered Product Admins - `utils.IsLayeredProductAdmin()` - `redhat-.*` namespace access
5. Regular Users - All others, strictest validation

## Testing

See [README.md](README.md) "Writing Unit Tests" and "Local Live Testing" for full guide.

**Unit Testing**:
- Use `pkg/testutils` helpers: `CreateFakeRequestJSON()`, `SendHTTPRequest()`
- Test all authorization levels (cluster-admin, SRE, privileged SA, regular users)
- Test validation logic for allowed and denied operations

**Test User Categories**:
1. Cluster admins
2. SRE groups
3. Privileged service accounts
4. Regular users

**Validation**: `make test` validates URI uniqueness and interface compliance

## Resource Generation

### SelectorSyncSet (Classic)
- Command: `make syncset`
- Output: [build/selectorsyncset.yaml](build/selectorsyncset.yaml)
- Control exclusions: Edit `SELECTOR_SYNC_SET_HOOK_EXCLUDES` in Makefile

### Package Operator (HyperShift)
- Command: `make package`
- Output: `build/package/*`
- Control exclusions: Edit `PACKAGE_HOOK_EXCLUDES` in Makefile

### Namespace Lists
- Command: `make generate`
- Output: [pkg/config/namespaces.go](pkg/config/namespaces.go)
- Source: OpenShift ConfigMaps (`openshift-config/openshift-install`, `openshift-config/openshift-update`)

## Protected Namespaces

**120+ namespaces** auto-generated from ConfigMaps with patterns:
- `^redhat-.*` - Red Hat managed
- `^openshift-.*` - OpenShift platform
- `^kube-.*` - Kubernetes system
- Plus: `default`, `openshift`, `kube-system`

Generated in [pkg/config/namespaces.go](pkg/config/namespaces.go) via `make generate`.

## Common Operations

### Disable Webhook Temporarily
Edit Makefile:
```makefile
SELECTOR_SYNC_SET_HOOK_EXCLUDES ?= debug-hook,unwanted-webhook
```
Then: `make syncset && make package`

### Remove Webhook Permanently
```bash
rm pkg/webhooks/add_mywebhook.go
rm -rf pkg/webhooks/mywebhook/
make all
# After deployment: oc delete validatingwebhookconfiguration sre-mywebhook
```

### Debug Webhook Issues
```bash
# Check pod logs
oc logs -n openshift-validation-webhook -l app=validation-webhook

# Verify configuration
oc get validatingwebhookconfiguration
oc describe validatingwebhookconfiguration sre-<webhook-name>
```

## CI/CD

- **Tekton Pipelines**: 4 configurations in `tekton/` for PR/push scenarios
- **App-Interface**: Automated deployment via GitLab app-interface
- **Registry**: Quay.io/app-sre/managed-cluster-validating-webhooks (git hash tags)
- **Base Image**: UBI9 Linux/AMD64

## Important Files

- [pkg/webhooks/register.go](pkg/webhooks/register.go) - Core interface & registration
- [cmd/main.go](cmd/main.go) - Main application entry point
- [pkg/dispatcher/dispatcher.go](pkg/dispatcher/dispatcher.go) - Request routing
- [pkg/config/namespaces.go](pkg/config/namespaces.go) - Protected namespaces (generated)
- [build/resources.go](build/resources.go) - Resource generation logic
- [Makefile](Makefile) - All build/test/generation commands
- [README.md](README.md) - Comprehensive development guide

## Best Practices

1. **Authorization First**: Check authorization before expensive validation
2. **Clear Errors**: Return actionable messages to users
3. **Test Coverage**: Test all authorization levels and edge cases
4. **Timeouts**: Keep `TimeoutSeconds()` at 2 seconds typically
5. **Failure Policy**: Use `Ignore` (fail-open) for non-critical webhooks
6. **Unique URIs**: Ensure `GetURI()` is unique (validated by `make test`)
7. **Idempotency**: Safe to call multiple times
8. **Documentation**: Update `Doc()` method with customer-facing explanation
