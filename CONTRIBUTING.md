# Contributing to Managed Cluster Validating Webhooks

Thank you for your interest in contributing to the Managed Cluster Validating Webhooks project! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment Setup](#development-environment-setup)
- [Contributing Process](#contributing-process)
- [Development Guidelines](#development-guidelines)
- [Testing](#testing)
- [Documentation](#documentation)
- [Review Process](#review-process)
- [Release Process](#release-process)

## Code of Conduct

This project follows the [OpenShift Community Code of Conduct](https://github.com/openshift/community/blob/main/CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- **Go**: Version 1.24.6 or later (see [go.mod](go.mod))
- **Container Runtime**: Docker or Podman
- **Kubernetes/OpenShift**: Access to a cluster for testing
- **Git**: For version control
- **Make**: For build automation

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/managed-cluster-validating-webhooks.git
   cd managed-cluster-validating-webhooks
   ```

3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/openshift/managed-cluster-validating-webhooks.git
   ```

## Development Environment Setup

### Build and Test Locally

1. **Install dependencies**:
   ```bash
   go mod download
   ```

2. **Run tests**:
   ```bash
   make test
   ```

3. **Build the binary**:
   ```bash
   make build
   ```

4. **Run locally for development**:
   ```bash
   make serve
   ```

5. **Format and vet code**:
   ```bash
   make vet
   ```

### Container Images

Build container images for testing:

```bash
# Build main webhook image
make build-image

# Build package image (for HyperShift)
make build-package-image
```

## Contributing Process

### 1. Create an Issue

- For bugs: Include detailed reproduction steps
- For features: Describe the use case and proposed solution
- Reference any related JIRA tickets (e.g., `SREP-XXXX`)

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 3. Make Changes

Follow the [development guidelines](#development-guidelines) below.

### 4. Test Your Changes

```bash
# Run unit tests
make test

# Run e2e tests (requires cluster access)
make e2e-binary-build
# See test/e2e/README.md for complete e2e testing instructions
```

### 5. Update Documentation

- Update relevant documentation
- Regenerate docs if needed:
  ```bash
  make docs > docs/webhooks.json
  make DOCFLAGS=-hideRules docs > docs/webhooks-short.json
  ```

### 6. Commit and Push

```bash
git add .
git commit -s -m "Brief description of change

Detailed explanation of what changed and why.

Fixes: #issue-number"
git push origin your-branch-name
```

**Note**: All commits must be signed off (`-s` flag) per the [Developer Certificate of Origin](https://developercertificate.org/).

### 7. Create Pull Request

- Use a descriptive title and detailed description
- Reference related issues with `Fixes #issue-number` or `Relates to #issue-number`
- Include JIRA ticket references if applicable
- Add appropriate labels

## Development Guidelines

### Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting (enforced by `make vet`)
- Use meaningful variable and function names
- Add comments for exported functions and complex logic

### Webhook Development

#### Adding a New Webhook

1. **Create webhook package**:
   ```bash
   mkdir pkg/webhooks/yourwebhook
   ```

2. **Implement the Webhook interface** (see [pkg/webhooks/register.go](pkg/webhooks/register.go)):
   ```go
   type Webhook interface {
       Name() string
       Rules() []admissionregv1.RuleWithOperations
       GetURI() string
       Validate(admissionctl.Request) bool
       Authorized(admissionctl.Request) admissionctl.Response
       // ... other required methods
   }
   ```

3. **Register the webhook** in `pkg/webhooks/add_yourwebhook.go`:
   ```go
   func init() {
       Register(yourwebhook.WebhookName, func() Webhook {
           return yourwebhook.NewWebhook()
       })
   }
   ```

4. **Write comprehensive tests**:
   - Unit tests in `pkg/webhooks/yourwebhook/yourwebhook_test.go`
   - E2E tests in `test/e2e/` if applicable

#### Webhook Best Practices

- **Fail gracefully**: Use `admissionregv1.Ignore` failure policy when appropriate
- **Performance**: Keep `TimeoutSeconds()` reasonable (typically 2-10 seconds)
- **Security**: Validate all inputs thoroughly
- **Logging**: Use structured logging with appropriate levels
- **Documentation**: Update webhook documentation with `make docs`

### Privileged Service Accounts

When adding service accounts that need special privileges:

1. **Add to regex pattern** in `pkg/webhooks/utils/utils.go`:
   ```go
   PrivilegedServiceAccountGroups = `^system:serviceaccounts:(pattern)|your-service-account`
   ```

2. **Document the reason** with JIRA ticket reference
3. **Write tests** to verify the exception works correctly

### Configuration Updates

- **Namespace lists**: Run `make generate` after modifying namespace configurations
- **SelectorSyncSet**: Run `make syncset` after webhook changes
- **Documentation**: Run `make docs` after functional changes

## Testing

### Unit Tests

```bash
# Run all unit tests
make test

# Run specific package tests
go test ./pkg/webhooks/namespace/

# Run with coverage
go test -cover ./pkg/webhooks/namespace/
```

### End-to-End Tests

```bash
# Build e2e test binary
make e2e-binary-build

# Run e2e tests (requires cluster access)
KUBECONFIG=/path/to/kubeconfig \
  ./bin/ginkgo --tags=osde2e -v test/e2e
```

### Test Requirements

- **Coverage**: Maintain or improve test coverage
- **Edge cases**: Test error conditions and edge cases
- **Security**: Test authorization and validation logic
- **Performance**: Consider performance implications

## Documentation

### Code Documentation

- Document all exported functions and types
- Use Go doc conventions
- Include usage examples for complex APIs

### Project Documentation

- Update README.md for user-facing changes
- Update webhook-specific documentation
- Add design documents in `designs/` for significant changes

### Generating Documentation

```bash
# Generate webhook documentation
make docs > docs/webhooks.json
make DOCFLAGS=-hideRules docs > docs/webhooks-short.json
```

## Review Process

### Reviewers and Approvers

See [OWNERS](OWNERS) file for current reviewers and approvers:
- **Reviewers**: Provide technical review and feedback
- **Approvers**: Have authority to approve changes for merging

### Review Criteria

1. **Functionality**: Does the change work as intended?
2. **Tests**: Are there adequate tests?
3. **Documentation**: Is documentation updated?
4. **Security**: Are security implications considered?
5. **Performance**: Is performance impact acceptable?
6. **Compatibility**: Are breaking changes documented?

### Addressing Review Feedback

- Address all review comments
- Push new commits (don't force-push during review)
- Mark conversations as resolved when addressed
- Re-request review after changes

## Release Process

### Versioning

This project follows semantic versioning principles:
- **Major**: Breaking changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, backward compatible

### Release Preparation

1. **Update dependencies**: Ensure all dependencies are up to date
2. **Run full test suite**: Including e2e tests
3. **Update documentation**: Ensure all docs are current
4. **Verify builds**: Ensure container images build successfully

### Container Images

Images are built and published automatically via CI/CD:
- **Registry**: `quay.io/app-sre/`
- **Main image**: `managed-cluster-validating-webhooks`
- **Package image**: `managed-cluster-validating-webhooks-hs-package`

## Getting Help

### Communication Channels

- **Issues**: [GitHub Issues](https://github.com/openshift/managed-cluster-validating-webhooks/issues)
- **JIRA**: Internal Red Hat JIRA for SREP team coordination

### Resources

- **OpenShift Documentation**: [Validating Admission Webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- **Kubernetes Documentation**: [Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- **Go Documentation**: [Effective Go](https://golang.org/doc/effective_go)

### Common Issues

#### Build Issues

```bash
# Clear module cache
go clean -modcache

# Update dependencies
go mod tidy
go mod download
```

#### Test Issues

```bash
# Verbose test output
go test -v ./pkg/webhooks/namespace/

# Run specific test
go test -run TestSpecificFunction ./pkg/webhooks/namespace/
```

#### Development Server Issues

```bash
# Check if port is available
netstat -tulpn | grep :8888

# Run with different port
go run ./cmd/main.go -port 9999
```

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (see [LICENSE](LICENSE)).

---

Thank you for contributing to Managed Cluster Validating Webhooks! Your contributions help make OpenShift more secure and reliable for all users.