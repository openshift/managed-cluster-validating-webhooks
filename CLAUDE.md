# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based Kubernetes validating/mutating webhooks framework for OpenShift Dedicated (OSD) and Red Hat OpenShift Service on AWS (ROSA) managed clusters. It implements 20+ webhooks that enforce security policies and operational constraints on managed clusters.

## Key Commands

```bash
# Development
make test              # Run tests and webhook validation
make build             # Build binary
make build-image       # Build container image
make build-package-image # Build PKO package for HyperShift

# Resource Generation
make syncset           # Generate SelectorSyncSet YAML for Classic clusters
make package           # Generate Package Operator resources for HyperShift
make docs              # Generate webhook documentation
make generate          # Update namespace lists from ConfigMaps

# Local Testing
make test-webhook WEBHOOK=namespace  # Test specific webhook
go test ./pkg/webhooks/namespace/... # Run webhook unit tests
```

## Architecture Overview

### Webhook Framework Design
- **Interface-Based**: All webhooks implement the `Webhook` interface in `pkg/webhooks/register.go`
- **Factory Pattern**: Webhooks register via `init()` functions in `add_*` files
- **Centralized Dispatcher**: Single HTTP server routes requests to webhooks based on URI paths
- **Plugin System**: Each webhook is a self-contained module in `pkg/webhooks/*/`

### Deployment Models
- **OSD/ROSA Classic**: Deployed as DaemonSet via SelectorSyncSet to master nodes
- **ROSA HyperShift**: Deployed via Package Operator (PKO) to hosted control plane

### Core Components
- **Main Application** (`cmd/main.go`): HTTP server with TLS, metrics, and webhook routing
- **Dispatcher** (`pkg/dispatcher/`): Thread-safe request routing and response handling
- **Individual Webhooks** (`pkg/webhooks/*/`): Modular webhook implementations
- **Configuration** (`pkg/config/`): Namespace protection lists and build-time config

## Adding New Webhooks

1. Create webhook directory: `pkg/webhooks/mywebhook/`
2. Implement the `Webhook` interface with required methods:
   - `Validate()`: Core webhook logic
   - `Authorized()`: Authorization checks
   - `GetURI()`: Unique webhook path
   - `Rules()`: AdmissionRules for K8s
3. Create registration file: `pkg/webhooks/add_mywebhook.go`
4. Add to Makefile webhook lists if needed
5. Update documentation with `make docs`

## Testing Guidelines

- **Unit Tests**: Use `pkg/testutils` for HTTP integration testing
- **Authorization Testing**: Test all user categories (cluster-admin, SRE, regular users)
- **Local Testing**: Follow README.md guide for testing on live clusters
- **Webhook Validation**: `make test` validates URI uniqueness and basic functionality

## Security Architecture

### Authorization Layers
1. **Cluster Admins**: `kube:admin`, `system:admin`, `backplane-cluster-admin`
2. **SRE Groups**: `system:serviceaccounts:openshift-backplane-srep`
3. **Privileged ServiceAccounts**: System service accounts with regex matching
4. **Layered Product Admins**: Special access for `redhat-.*` namespaces
5. **Regular Users**: Most restrictive validation

### Namespace Protection
- **120+ Protected Namespaces**: Auto-generated from OpenShift ConfigMaps
- **Pattern Matching**: `^redhat-.*`, `^openshift-.*`, `^kube-.*` patterns
- **Label Protection**: Categories of immutable/removable protected labels

## Resource Generation

Build system generates Kubernetes resources dynamically:
- **SelectorSyncSet**: For Classic OSD/ROSA deployments
- **Package Operator**: For HyperShift deployments
- **Webhook Inclusion**: Control via `REGISTRY_*` Makefile variables
- **Namespace Lists**: Auto-generated from cluster ConfigMaps

## CI/CD Integration

- **Tekton Pipelines**: 4 configurations for PR/push scenarios in `tekton/`
- **App-Interface**: Automated deployment via GitLab app-interface
- **Multi-arch Builds**: Linux/AMD64 with UBI9 base images
- **Registry**: Quay.io with git hash tagging

## Important Files

- `pkg/webhooks/register.go`: Core webhook interface and registration
- `pkg/config/namespaces.go`: Protected namespace definitions
- `build/resources.go`: Dynamic resource generation logic
- `cmd/main.go`: Main application entry point
- `pkg/dispatcher/`: Request routing and response handling
- `Makefile`: All build, test, and generation commands