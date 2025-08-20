# Docker Image Verification with Notation

This guide provides comprehensive instructions for verifying the authenticity and integrity of the AWS IAM Roles Anywhere Credential Helper Docker images using [Notation](https://notaryproject.dev/), a CNCF project that implements the Notary v2 specification for container image signing and verification.

## Overview

The AWS IAM Roles Anywhere Credential Helper Docker images are signed using AWS Signer, and you can verify these signatures using Notation to ensure you're using legitimate, untampered images from AWS.

## Prerequisites

- Docker or compatible container runtime
- Internet access for downloading Notation and certificates

## Installation

### Install Notation CLI

#### Linux (x86_64)
```bash
# Download and install the latest Notation release
curl -Lo notation.tar.gz "https://github.com/notaryproject/notation/releases/download/v1.1.0/notation_1.1.0_linux_amd64.tar.gz"
tar xvzf notation.tar.gz
sudo mv notation /usr/local/bin/
```

#### macOS
```bash
# Using Homebrew
brew install notation

# Or download directly
curl -Lo notation.tar.gz "https://github.com/notaryproject/notation/releases/download/v1.1.0/notation_1.1.0_darwin_amd64.tar.gz"
tar xvzf notation.tar.gz
sudo mv notation /usr/local/bin/
```

#### Windows
```powershell
# Download from GitHub releases
# https://github.com/notaryproject/notation/releases/download/v1.1.0/notation_1.1.0_windows_amd64.zip
# Extract and add to PATH
```

#### Verify Installation
```bash
notation version
```

### Install AWS Signer Plugin

The AWS Signer plugin is required to verify signatures created by AWS Signer:

```bash
notation plugin install --url https://d2hvyiie56hcat.cloudfront.net/linux/amd64/plugin/latest/notation-aws-signer-plugin.zip
```

For other platforms, visit the [AWS Signer plugin releases](https://github.com/aws/aws-signer-notation-plugin/releases).

## Trust Policy Setup

Notation uses trust policies to define which signatures to trust. This directory contains two pre-configured trust policy files:

### Standard Trust Policy (`notationtrustpolicy.json`)
- **Use case**: Production environments with full certificate validation
- **Features**: Strict signature verification with revocation checking
- **Recommended for**: Most production use cases

### Skip Revocation Trust Policy (`notationtrustpolicyskiprevocation.json`)
- **Use case**: Environments where certificate revocation checking may fail due to network restrictions
- **Features**: Signature verification without revocation checking
- **Recommended for**: Air-gapped environments or networks with restricted internet access

### Configure Trust Policy

Choose the appropriate trust policy for your environment:

#### For standard environments (recommended):
```bash
notation policy import ./notationtrustpolicy.json
```

#### For environments with network restrictions:
```bash
notation policy import ./notationtrustpolicyskiprevocation.json
```

### Verify Trust Policy Configuration
```bash
notation policy show
```

## Trust Store Setup

Configure the trust store with AWS Signer certificates:

```bash
# Add AWS Signer trust store for commercial regions
notation cert add --type signingAuthority --store aws-signer-ts \
  <(curl -s https://truststore.pki.aws.amazon.com/aws-signer/aws-signer-2023.crt)

# Add AWS Signer trust store for GovCloud regions  
notation cert add --type signingAuthority --store aws-us-gov-signer-ts \
  <(curl -s https://truststore.pki.aws.amazon.com/aws-signer/aws-us-gov-signer-2023.crt)
```

### Verify Trust Store Configuration
```bash
notation cert list
```

## Image Verification

### Basic Verification Command

To verify a Docker image, use the following command format:

```bash
notation verify <image> --plugin-config aws-region=us-east-1
```

### Examples

#### Verify latest image:
```bash
notation verify public.ecr.aws/aws-cli/aws-iam-roles-anywhere-credential-helper:latest --plugin-config aws-region=us-east-1
```

#### Verify specific version:
```bash
notation verify public.ecr.aws/aws-cli/aws-iam-roles-anywhere-credential-helper:v1.1.0 --plugin-config aws-region=us-east-1
```

#### Verify with verbose output:
```bash
notation verify public.ecr.aws/aws-cli/aws-iam-roles-anywhere-credential-helper:latest \
  --plugin-config aws-region=us-east-1 \
  --verbose
```

### Successful Verification Output

A successful verification will show output similar to:
```
Successfully verified signature for public.ecr.aws/aws-cli/aws-iam-roles-anywhere-credential-helper:latest
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Plugin Not Found Error
```
Error: plugin "aws-signer-plugin" not found
```

**Solution**: Install the AWS Signer plugin:
```bash
notation plugin install --url https://d2hvyiie56hcat.cloudfront.net/linux/amd64/plugin/latest/notation-aws-signer-plugin.zip
```

#### 2. Trust Policy Not Found
```
Error: trust policy statement "aws-signer-tp" is not found
```

**Solution**: Import the trust policy:
```bash
notation policy import ./notationtrustpolicy.json
```

#### 3. Certificate Revocation Check Failed
```
Error: certificate revocation check failed
```

**Solutions**:
- Use the skip revocation trust policy for network-restricted environments:
  ```bash
  notation policy import ./notationtrustpolicyskiprevocation.json
  ```
- Ensure internet access for revocation checking
- Check firewall settings for OCSP/CRL access

#### 4. Trust Store Certificate Missing
```
Error: signing certificate not found in trust store
```

**Solution**: Add the AWS Signer certificates to the trust store:
```bash
notation cert add --type signingAuthority --store aws-signer-ts \
  <(curl -s https://truststore.pki.aws.amazon.com/aws-signer/aws-signer-2023.crt)
```

#### 5. Region Configuration Issues
```
Error: failed to verify signature
```

**Solution**: Ensure you're using the correct AWS region in the plugin configuration. The signing was performed in `us-east-1`:
```bash
notation verify <image> --plugin-config aws-region=us-east-1
```

#### 6. Network Connectivity Issues
```
Error: failed to download certificate
```

**Solutions**:
- Check internet connectivity
- Verify proxy settings if behind a corporate firewall
- For air-gapped environments, manually download and add certificates:
  ```bash
  # Download certificate manually and add to trust store
  curl -o aws-signer-2023.crt https://truststore.pki.aws.amazon.com/aws-signer/aws-signer-2023.crt
  notation cert add --type signingAuthority --store aws-signer-ts aws-signer-2023.crt
  ```

### Debug Mode

For detailed troubleshooting information, run verification with debug logging:

```bash
NOTATION_LOG_LEVEL=debug notation verify <image> --plugin-config aws-region=us-east-1
```

### Verify Configuration

To check your current Notation configuration:

```bash
# Check trust policies
notation policy show

# Check certificates
notation cert list

# Check plugins
notation plugin list
```

## Security Best Practices

1. **Always verify images before use**: Make image verification part of your deployment pipeline
2. **Use appropriate trust policy**: Choose between standard and skip-revocation based on your environment
3. **Keep certificates updated**: Regularly update trust store certificates
4. **Monitor for updates**: Stay informed about updates to Notation and the AWS Signer plugin
5. **Validate trust policies**: Regularly review and validate your trust policy configuration

## Additional Resources

- [Notation Documentation](https://notaryproject.dev/docs/)
- [AWS Signer Documentation](https://docs.aws.amazon.com/signer/)
- [Notary v2 Specification](https://github.com/notaryproject/specifications)
- [AWS Signer Notation Plugin](https://github.com/aws/aws-signer-notation-plugin)

## Support

For issues related to:
- **Notation CLI**: [Notation GitHub Issues](https://github.com/notaryproject/notation/issues)
- **AWS Signer Plugin**: [AWS Signer Plugin Issues](https://github.com/aws/aws-signer-notation-plugin/issues)
- **AWS IAM Roles Anywhere**: [AWS Support](https://aws.amazon.com/support/)