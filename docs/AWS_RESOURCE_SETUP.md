# AWS resource setup

This guide covers the AWS resources required by `nova_act_auth` and the NovaAct SDK's session persistence features. Each section links to the relevant AWS documentation and provides the CLI commands to create the resource.

The CLI commands below create **reference resources** with minimal configuration to get started quickly. Before deployment, review and adapt them to your security requirements (e.g., advanced threat protection, WAF, VPC endpoints, stricter IAM policies, logging).

> **Cost notice:** The resources in this guide (Amazon Cognito, Amazon S3, AWS KMS, Amazon Verified Permissions, Amazon Bedrock AgentCore) incur AWS charges. Review the pricing pages for each service before creating resources in a live AWS account.

This guide follows the [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/): AWS secures the underlying infrastructure for Amazon Cognito, Amazon S3, AWS KMS, Amazon Verified Permissions, and Amazon Bedrock AgentCore. Customers are responsible for the configurations in this guide, including IAM policies, encryption key management, bucket policies, and authorization rules.

## Prerequisites

- AWS CLI v2 installed and configured (`aws configure`)
- An AWS account with permissions to create the resources below
- Python 3.11+ (for running the library and samples)

## Overview

| Resource | Used by | Purpose |
|----------|---------|---------|
| Cognito User Pool | `nova_act_auth` | SSO identity gate - PKCE OAuth2 flow |
| Verified Permissions | `VerifiedPermissionsPolicy` | Cedar-based authorization (optional) |
| S3 Bucket | `S3TokenStore`, `S3SessionProvider` | Token and browser session persistence |
| AWS KMS key | S3 bucket encryption | SSE-KMS encryption at rest |
| AgentCore Browser | `AgentCoreBrowserCallback` | SSO callback in headless/cloud environments |

## 1. Cognito User Pool

Cognito provides the OAuth2/OIDC infrastructure for SSO. The library uses the authorization code flow with PKCE (no client secret).

> **Note:** Cognito supports both OIDC and SAML 2.0 identity providers. This library has only been tested with OIDC IdPs (Okta, Microsoft Entra ID), but any OIDC-compliant provider should work.

### What gets created

- **User Pool** - the identity directory
- **Hosted UI domain** - the login page URL (`https://{prefix}.auth.{region}.amazoncognito.com`)
- **OIDC identity provider** - federation with any OIDC-compliant IdP (Okta, Entra ID, Google Workspace, Auth0, Ping Identity, Keycloak, etc.)
- **App Client** - public client (no secret) with PKCE, configured callback URLs

### AWS documentation

- [Getting started with Amazon Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-getting-started.html)
- [Add an app client with the hosted UI (tutorial)](https://docs.aws.amazon.com/cognito/latest/developerguide/tutorial-create-hosted-ui-app-client.html)
- [Using PKCE in authorization code grants](https://docs.aws.amazon.com/cognito/latest/developerguide/using-pkce-in-authorization-code.html)
- [Using OIDC identity providers with a user pool](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-oidc-idp.html)
- [Configuring a user pool domain](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain.html)

### CLI setup

### Minimum IAM permissions

The steps below require the following IAM permissions:

```json
[
  {
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "cognito-idp:CreateUserPool",
      "cognito-idp:ListUserPools"
    ],
    "Resource": "*"
  },
  {
    "Effect": "Allow",
    "Action": [
      "cognito-idp:DeleteUserPool",
      "cognito-idp:DescribeUserPool",
      "cognito-idp:CreateUserPoolDomain",
      "cognito-idp:DeleteUserPoolDomain",
      "cognito-idp:DescribeUserPoolDomain",
      "cognito-idp:CreateIdentityProvider",
      "cognito-idp:DeleteIdentityProvider",
      "cognito-idp:ListIdentityProviders",
      "cognito-idp:CreateUserPoolClient",
      "cognito-idp:DeleteUserPoolClient",
      "cognito-idp:ListUserPoolClients"
    ],
    "Resource": "arn:aws:cognito-idp:*:*:userpool/*"
  }
]
```

`sts:GetCallerIdentity`, `cognito-idp:CreateUserPool`, and `cognito-idp:ListUserPools` require `"Resource": "*"` because they are account-level operations with no pre-existing resource ARN to scope to. All other Cognito actions are scoped to `arn:aws:cognito-idp:*:*:userpool/*`.

> **Best practice:** The account-level actions above (`sts:GetCallerIdentity`, `cognito-idp:CreateUserPool`, `cognito-idp:ListUserPools`) cannot be scoped to a specific resource ARN. Add a `Condition` block to restrict them by region or source IP:
> ```json
> "Condition": {
>   "StringEquals": {
>     "aws:RequestedRegion": ["us-east-1"]
>   }
> }
> ```

The second statement (pool-scoped actions) includes `Delete*` and `List*` which are only needed if you want to clean up resources. If you only need to create resources, use this reduced policy instead:

```json
[
  {
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "cognito-idp:CreateUserPool",
      "cognito-idp:ListUserPools"
    ],
    "Resource": "*"
  },
  {
    "Effect": "Allow",
    "Action": [
      "cognito-idp:DescribeUserPool",
      "cognito-idp:CreateUserPoolDomain",
      "cognito-idp:DescribeUserPoolDomain",
      "cognito-idp:CreateIdentityProvider",
      "cognito-idp:CreateUserPoolClient"
    ],
    "Resource": "arn:aws:cognito-idp:*:*:userpool/*"
  }
]
```

Run the steps manually:

```bash
REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
DOMAIN_PREFIX="my-agent-${ACCOUNT_ID}"

# 1. Create User Pool
USER_POOL_ID=$(aws cognito-idp create-user-pool \
  --pool-name "my-agent-users" \
  --auto-verified-attributes email \
  --region "${REGION}" \
  --query 'UserPool.Id' --output text)

# 2. Create Hosted UI domain
aws cognito-idp create-user-pool-domain \
  --domain "${DOMAIN_PREFIX}" \
  --user-pool-id "${USER_POOL_ID}" \
  --region "${REGION}"

# 3. Add OIDC identity provider (see "Identity provider setup" below)
aws cognito-idp create-identity-provider \
  --user-pool-id "${USER_POOL_ID}" \
  --provider-name "YOUR_IDP_NAME" \
  --provider-type "OIDC" \
  --provider-details '{
    "client_id": "<IDP_CLIENT_ID>",
    "client_secret": "<IDP_CLIENT_SECRET>",
    "authorize_scopes": "openid profile email",
    "oidc_issuer": "<IDP_ISSUER_URL>"
  }' \
  --attribute-mapping '{"email":"email","name":"name","username":"sub"}' \
  --region "${REGION}"

# 4. Create public App Client (PKCE, no secret)
CLIENT_ID=$(aws cognito-idp create-user-pool-client \
  --user-pool-id "${USER_POOL_ID}" \
  --client-name "my-agent-cli" \
  --no-generate-secret \
  --allowed-o-auth-flows "code" \
  --allowed-o-auth-scopes "openid" "profile" "email" \
  --allowed-o-auth-flows-user-pool-client \
  --supported-identity-providers "COGNITO" "YOUR_IDP_NAME" \
  --callback-urls \
    "http://localhost:8976/callback" \
    "https://auth.callback.internal/callback" \
  --region "${REGION}" \
  --query 'UserPoolClient.ClientId' --output text)
```

### Callback URLs

The App Client needs two callback URLs registered:

| URL | Used by |
|-----|---------|
| `http://localhost:8976/callback` | `LocalhostCallback` - local development. HTTP is used because the loopback interface is exempt from TLS for native app OAuth callbacks per [RFC 8252 §8.3](https://datatracker.ietf.org/doc/html/rfc8252#section-8.3). |
| `https://auth.callback.internal/callback` | `AgentCoreBrowserCallback` and `PlaywrightLocalCallback` - does not resolve to a real server; the library intercepts the redirect before the page loads. |

The port `8976` matches the default `AuthConfig.callback_port`. If you change it, update the callback URL accordingly.

### Identity provider setup

Cognito federates with any OIDC-compliant identity provider. The library talks to Cognito, not to the IdP directly, so any IdP that supports OIDC works: Okta, Microsoft Entra ID, Google Workspace, Auth0, Ping Identity, OneLogin, Keycloak, AWS IAM Identity Center, or any custom OIDC provider. Cognito also supports SAML 2.0 IdPs, but this library has only been tested with OIDC.

The OIDC issuer URL and client credentials come from your IdP. You need to register an application in the IdP first, then use those credentials when creating the Cognito identity provider. The steps below document Okta and Entra ID as examples - the same pattern applies to any OIDC IdP.

#### Okta

1. In the Okta Admin Console, go to **Applications > Create App Integration**
2. Select **OIDC - OpenID Connect** and **Web Application**
3. Set the sign-in redirect URI to your Cognito callback:
   `https://{domain-prefix}.auth.{region}.amazoncognito.com/oauth2/idpresponse`
4. Note the **Client ID**, **Client Secret**, and **Okta domain**
5. The OIDC issuer URL is `https://{your-org}.okta.com`

Okta docs: [Create OIDC app integrations](https://developer.okta.com/docs/guides/sign-into-web-app-redirect/main/)

#### Microsoft Entra ID (Azure AD)

1. In the Azure Portal, go to **App registrations > New registration**
2. Set the redirect URI (Web) to your Cognito callback:
   `https://{domain-prefix}.auth.{region}.amazoncognito.com/oauth2/idpresponse`
3. Under **Certificates & secrets**, create a client secret
4. Note the **Application (client) ID**, **Client Secret**, and **Directory (tenant) ID**
5. The OIDC issuer URL is `https://login.microsoftonline.com/{tenant-id}/v2.0`

Microsoft docs: [Register an application with the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)

> **Important:** SSO will fail with an "invalid redirect URI" error if the Cognito callback URL is not registered in your IdP application. The callback URL follows this pattern: `https://{domain-prefix}.auth.{region}.amazoncognito.com/oauth2/idpresponse`
>
> Configure this in your IdP **before** attempting the first SSO login.

#### Chicken-and-egg: IdP needs Cognito URL, Cognito needs IdP credentials

The IdP redirect URI contains the Cognito domain prefix, but you need IdP credentials to create the Cognito identity provider. Two approaches:

1. **Pre-compute the URL** (recommended) - the domain prefix is deterministic (e.g., `my-agent-{account_id}`), so compute the full callback URL before creating the IdP app.
2. **Two-phase setup** - create the IdP app with a placeholder redirect URI, get the credentials, deploy Cognito, then update the IdP redirect URI.

### Environment variables

After setup, configure these for the library:

```bash
export AGENT_AUTH_COGNITO_DOMAIN='{domain-prefix}.auth.{region}.amazoncognito.com'
export AGENT_AUTH_COGNITO_CLIENT_ID='{client-id}'
export AGENT_AUTH_IDP_NAME='{provider-name}'  # IdP name as configured in Cognito (optional)
```

See `AuthConfig.from_env()` for the full list.

### Customizing the Hosted UI

Cognito's Hosted UI is the login page users see during SSO. By default it has a minimal design, but you can customize it with your organization's branding:

- **Logo** - upload a custom logo image
- **CSS** - override colors, fonts, and layout with a custom CSS file
- **Custom domain** - use your own domain (e.g., `login.example.com`) instead of the default `{prefix}.auth.{region}.amazoncognito.com`

Customization is done in the Cognito console under **App integration > Hosted UI customization**, or via the CLI:

```bash
# Upload a logo
aws cognito-idp set-ui-customization \
  --user-pool-id "${USER_POOL_ID}" \
  --image-file fileb://logo.png \
  --region "${REGION}"

# Upload custom CSS
aws cognito-idp set-ui-customization \
  --user-pool-id "${USER_POOL_ID}" \
  --css ".banner-customizable { background: #1a73e8; }" \
  --region "${REGION}"
```

For a fully custom domain:

```bash
# Requires an ACM certificate in us-east-1
aws cognito-idp create-user-pool-domain \
  --domain "login.example.com" \
  --user-pool-id "${USER_POOL_ID}" \
  --custom-domain-config CertificateArn="arn:aws:acm:us-east-1:123456789012:certificate/abc-123" \
  --region "${REGION}"
```

> **Note:** If `identity_provider` is set in `AuthConfig`, the Hosted UI is bypassed entirely - users are redirected straight to the IdP's login page. UI customization only applies when users see the Cognito Hosted UI (e.g., when choosing between multiple IdPs).

AWS docs:
- [Customizing the Hosted UI](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-ui-customization.html)
- [Using your own domain for the Hosted UI](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-add-custom-domain.html)
- [Managed login branding (new style)](https://docs.aws.amazon.com/cognito/latest/developerguide/managed-login-branding.html)

### Cognito federation references and samples

| Resource | Description | Use case | Library | Infra |
|----------|-------------|----------|---------|-------|
| [aws-cognito-okta-federation](https://github.com/aws-samples/aws-cognito-okta-federation) | Authorization code grant with Cognito + Okta OIDC. Closest match to our setup. | Okta as OIDC IdP with Cognito | Works as-is | Follow the sample |
| [amazon-cognito-example-for-external-idp](https://github.com/aws-samples/amazon-cognito-example-for-external-idp) | Cognito + external OIDC IdP with CDK. Includes [Okta instructions](https://github.com/aws-samples/amazon-cognito-example-for-external-idp/blob/master/docs/OktaInstructions.md) and IdP attribute mapping. | CDK-based Cognito + IdP deployment | Works as-is | Follow the sample (CDK) |
| [amazon-cognito-example-for-multi-tenant](https://github.com/aws-samples/amazon-cognito-example-for-multi-tenant) | Single User Pool with multiple external IdPs (Okta, Entra ID, AD FS). | Multi-tenant setups with different IdPs per customer | Works as-is; may need a custom `SessionKeyBuilder` to include tenant ID | Follow the sample; additional IdP registration per tenant |
| [cognito-external-idp-proxy](https://github.com/aws-samples/cognito-external-idp-proxy) | Proxy between Cognito and an OIDC IdP using private key JWT and PKCE. | Advanced: IdPs that require private key JWT client auth | Works as-is (library talks to Cognito, not the proxy) | Deploy the proxy + standard Cognito setup |
| [How to set up Cognito for federated auth using Azure AD](https://aws.amazon.com/blogs/security/how-to-set-up-amazon-cognito-for-federated-authentication-using-azure-ad/) | Step-by-step Security Blog post for Entra ID (Azure AD) federation. | Entra ID as OIDC IdP with Cognito | Works as-is | Follow the blog post |
| [How to use OAuth 2.0 in Amazon Cognito](https://aws.amazon.com/blogs/security/how-to-use-oauth-2-0-in-amazon-cognito-learn-about-the-different-oauth-2-0-grants/) | Explains authorization code + PKCE grant, implicit grant, and client credentials. | Understanding which OAuth flow to use | Handled by the library | N/A |
| [Choose a Cognito auth flow for enterprise applications](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/choose-an-amazon-cognito-authentication-flow-for-enterprise-applications.html) | AWS Prescriptive Guidance pattern for selecting the right auth flow. | Enterprise auth flow decision-making | Handled by the library | N/A |
| [Using PKCE in authorization code grants](https://docs.aws.amazon.com/cognito/latest/developerguide/using-pkce-in-authorization-code.html) | Official Cognito docs on PKCE. This is the flow used by `nova_act_auth`. | PKCE implementation reference | Handled by the library | N/A |
| [Configuring identity providers for your user pool](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-identity-provider.html) | Overview of adding OIDC IdPs to a Cognito User Pool. | Adding any OIDC IdP to Cognito | Works as-is | Follow the guide for your IdP |


### Troubleshooting

**Domain already in use**

Cognito domain prefixes are globally unique. If you see "Domain already associated with another user pool", either use a different prefix or clean up the pool that owns the domain:

```bash
# Find pools
aws cognito-idp list-user-pools --max-results 20 --region us-east-1

# Delete the pool that owns the domain
aws cognito-idp delete-user-pool-domain --domain <prefix> --user-pool-id <pool-id> --region us-east-1
aws cognito-idp delete-user-pool --user-pool-id <pool-id> --region us-east-1
```

**Issuer URL rejected**

The OIDC issuer URL must start with `https://`. If you see an error about the issuer URL, check that you included the scheme (e.g., `https://your-org.okta.com`, not `your-org.okta.com`).


## 2. Verified Permissions (optional)

Used by `VerifiedPermissionsPolicy` for Cedar-based authorization. See [`AUTHORIZATION.md`](AUTHORIZATION.md) for the full guide including Cedar policy examples and schema setup.

### AWS documentation

- [What is Amazon Verified Permissions?](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html)
- [Working with Cognito identity sources](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/identity-sources-cognito.html)
- [Cedar policy language reference](https://docs.cedarpolicy.com/)

### CLI setup (minimum)

Three commands to create a policy store that permits all authenticated users. Cedar policies can be added later to restrict access.

```bash
REGION="us-east-1"
USER_POOL_ID="us-east-1_abc123"
CLIENT_ID="your-app-client-id"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# 1. Create policy store
POLICY_STORE_ID=$(aws verifiedpermissions create-policy-store \
  --validation-settings "mode=OFF" \
  --description "Agent authorization" \
  --region "${REGION}" \
  --query 'policyStoreId' --output text)

# 2. Connect Cognito as identity source
aws verifiedpermissions create-identity-source \
  --policy-store-id "${POLICY_STORE_ID}" \
  --principal-entity-type "Agent::User" \
  --configuration '{
    "cognitoUserPoolConfiguration": {
      "userPoolArn": "arn:aws:cognito-idp:'${REGION}':'${ACCOUNT_ID}':userpool/'${USER_POOL_ID}'",
      "clientIds": ["'${CLIENT_ID}'"],
      "groupConfiguration": {
        "groupEntityType": "Agent::UserGroup"
      }
    }
  }' \
  --region "${REGION}"

# 3. Permit all authenticated users (least restrictive default)
aws verifiedpermissions create-policy \
  --policy-store-id "${POLICY_STORE_ID}" \
  --definition '{
    "static": {
      "description": "Permit all authenticated users",
      "statement": "permit(principal, action, resource);"
    }
  }' \
  --region "${REGION}"
```

### IAM permissions

```json
{
  "Effect": "Allow",
  "Action": "verifiedpermissions:IsAuthorizedWithToken",
  "Resource": "arn:aws:verifiedpermissions:{region}:{account}:policy-store/{policy-store-id}"
}
```

### Skipping Verified Permissions

Verified Permissions is optional. Use `AllowAllPolicy`, `AllowedDomainsPolicy`, or a custom `AuthorizationPolicy` subclass if you don't need externalized Cedar policies.


## 3. S3 bucket (token and session storage)

Used by `S3TokenStore` (this library) and `S3SessionProvider` (NovaAct SDK) to persist tokens and browser session state with SSE-KMS encryption.

### AWS documentation

- [Configuring default encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html)
- [Using server-side encryption with AWS KMS keys (SSE-KMS)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)
- [Configuring S3 Bucket Key with SSE-KMS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-bucket-key.html)

### CLI setup

```bash
BUCKET="nova-act-session-store-${ACCOUNT_ID}"
REGION="us-east-1"

# 1. Create bucket
aws s3api create-bucket \
  --bucket "${BUCKET}" \
  --region "${REGION}"

# 2. Block public access
aws s3api put-public-access-block \
  --bucket "${BUCKET}" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 3. Enforce HTTPS-only access (encryption in transit)
aws s3api put-bucket-policy \
  --bucket "${BUCKET}" \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::'"${BUCKET}"'",
        "arn:aws:s3:::'"${BUCKET}"'/*"
      ],
      "Condition": {
        "Bool": { "aws:SecureTransport": "false" }
      }
    }]
  }'

# 4. Set SSE-KMS default encryption (requires AWS KMS key from section 4)
aws s3api put-bucket-encryption \
  --bucket "${BUCKET}" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "alias/nova-act-sessions"
      },
      "BucketKeyEnabled": true
    }]
  }'

# 5. Enable versioning (protects against accidental deletion or overwrite)
aws s3api put-bucket-versioning \
  --bucket "${BUCKET}" \
  --versioning-configuration Status=Enabled

# Note: for buckets storing sensitive tokens, consider enabling
# MFA Delete on the versioned bucket. MFA Delete requires the bucket owner's
# root account credentials and prevents version deletion without MFA
# confirmation - providing an additional protection layer against accidental
# or malicious removal of token objects. See:
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html

# 6. Enable server access logging (required for security audit trails and compliance)
LOG_BUCKET="${BUCKET}-logs"
aws s3api create-bucket \
  --bucket "${LOG_BUCKET}" \
  --region "${REGION}"
aws s3api put-bucket-logging \
  --bucket "${BUCKET}" \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "'"${LOG_BUCKET}"'",
      "TargetPrefix": "s3-access-logs/"
    }
  }'
```

For complete object-level audit coverage, enable CloudTrail S3 data event logging in addition to S3 server access logging. CloudTrail captures GetObject, PutObject, and DeleteObject calls with the IAM identity of the requester:

```bash
aws cloudtrail put-event-selectors \
  --trail-name your-trail-name \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": false,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::'"${BUCKET}"'/"]
    }]
  }]'
```

### Key prefixes

The bucket is shared between this library and the SDK:

| Prefix | Written by | Contents |
|--------|-----------|----------|
| `tokens/` | `S3TokenStore` | Cognito JWT tokens (`AuthResult`) |
| `nova-act-sessions/` | `S3SessionProvider` (SDK) | Browser state (cookies, localStorage) |

### Data classification

| Data | Sensitivity | Retention guidance |
|------|-------------|-------------------|
| Cognito access and ID tokens (`tokens/` prefix) | High - treat like API keys | Delete when expired (~1 hour TTL); `get_or_authenticate --purge` removes them |
| Cognito refresh tokens (`tokens/` prefix) | Critical - long-lived credential | Delete on logout or compromise; 30-day TTL by default |
| Browser session state (`nova-act-sessions/` prefix) | High | Delete when the session is no longer needed |
| Profile-to-session-key mappings (`keys/` prefix) | Medium - contains user email | Delete alongside the corresponding token |

### IAM permissions

The agent's IAM role needs:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
  "Resource": [
    "arn:aws:s3:::{bucket}/tokens/*",
    "arn:aws:s3:::{bucket}/nova-act-sessions/*"
  ]
}
```

### Environment variables

```bash
export AGENT_AUTH_S3_BUCKET='{bucket-name}'
export AGENT_AUTH_S3_KMS_KEY='alias/nova-act-sessions'
```

### Skipping S3

S3 is required for token persistence. If you do not need token caching (the agent will run a full SSO flow on every start), you can implement `TokenStore` with a custom backend or skip persistence entirely by providing a no-op store. The SDK's `LocalFileSessionProvider` does not require S3 and can be used for browser session persistence independently.


## 4. AWS KMS key

Provides encryption at rest for the S3 bucket. If you already have an AWS KMS key you want to use, skip to "Using an existing key".

### AWS documentation

- [Creating keys](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html)
- [Creating aliases](https://docs.aws.amazon.com/kms/latest/developerguide/alias-create.html)

### CLI setup

> **Security review:** Customer-managed KMS keys (the BYOK pattern used here) should be reviewed by your security team before deployment. Verify the key policy, rotation configuration, and that the key is scoped to the intended principals. For development and test environments you may proceed, but flag this for a security review before wider deployment.

```bash
# 1. Create key with automatic annual rotation enabled
KEY_ID=$(aws kms create-key \
  --description "Encryption key for nova-act session and token storage" \
  --enable-key-rotation \
  --region "${REGION}" \
  --query 'KeyMetadata.KeyId' --output text)

# 2. Create alias
aws kms create-alias \
  --alias-name "alias/nova-act-sessions" \
  --target-key-id "${KEY_ID}" \
  --region "${REGION}"
```

### Key management notes

- **Rotation:** Automatic annual rotation is enabled by the `--enable-key-rotation` flag. AWS KMS re-wraps data keys transparently so no application re-encryption is needed.
- **Deletion:** KMS keys have a minimum 7-day waiting period (default 30 days). Review which S3 objects are encrypted with the key before scheduling deletion.
- **Recovery:** KMS keys are automatically replicated within their AWS region. For cross-region disaster recovery, create a separate key in each region.

### IAM permissions

The agent's IAM role needs:

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey*",
    "kms:DescribeKey"
  ],
  "Resource": "arn:aws:kms:{region}:{account}:key/{key-id}"
}
```

If you use `grant_encrypt_decrypt` in CDK or the default key policy (account root has full access), this is handled automatically.

### Using an existing key

Pass the key ID or alias wherever the library or SDK accepts an AWS KMS key:

```bash
export AGENT_AUTH_S3_KMS_KEY='alias/my-existing-key'
# or
export AGENT_AUTH_S3_KMS_KEY='arn:aws:kms:us-east-1:123456789012:key/abc-123'
```


## 5. Amazon Bedrock AgentCore Browser

Used by the `AgentCoreBrowserCallback` strategy for SSO in headless or cloud environments. The user completes SSO in the AWS console's Live View. Also used by the SDK's `AgentCoreBrowserSessionProvider` for browser session persistence via server-side profiles.

### AWS documentation

- [Get started with AgentCore Browser](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-onboarding.html)
- [Creating an AgentCore Browser](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-create.html)
- [Using browser profiles](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-profiles.html)
- [Starting a browser session](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-start-session.html)
- [Using AgentCore Browser with other libraries](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-building-agents.html)

#### IdP integration with AgentCore Identity

If your agent uses AgentCore Identity for federated authentication:

- [Okta setup for AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idp-okta.html)
- [Microsoft Entra ID setup for AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idp-microsoft.html)
- [Auth0 by Okta setup](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idp-auth0.html)

### CLI setup

AgentCore Browser setup is fully covered in the AWS documentation above. The key commands:

```bash
REGION="us-east-1"

# Create a browser (public network mode)
aws bedrock-agentcore-control create-browser \
  --region "${REGION}" \
  --name "my-browser" \
  --network-configuration '{"networkMode": "PUBLIC"}'

# Start a session
aws bedrock-agentcore start-browser-session \
  --region "${REGION}" \
  --browser-identifier "my-browser" \
  --name "sso-session" \
  --session-timeout-seconds 900

# Save a browser profile after authentication
aws bedrock-agentcore save-browser-session-profile \
  --region "${REGION}" \
  --profile-identifier "my-profile" \
  --browser-identifier "my-browser" \
  --session-id "<session-id>"
```

In practice, the `bedrock-agentcore` Python SDK handles session management. See the [AgentCore Browser getting started guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-onboarding.html) for prerequisites and IAM permissions.

### DCV live streaming

This library does not provide the ability to live stream an AgentCore Browser session using DCV (NICE DCV). For real-time remote control of the agent's browser - where a human operator can view and interact with a running session via encrypted pixel streaming over WebSocket - see the [Nova Act Human Intervention Service](https://github.com/amazon-agi-labs/nova-act-human-intervention). That project provides a reference implementation for human-in-the-loop patterns (approval and UI takeover) with DCV streaming, including a Python SDK, AWS CDK infrastructure, and a single-page application for human operators.

### When is AgentCore Browser needed?

| Scenario | AgentCore needed? |
|----------|-------------------|
| Local development with system browser (`LocalhostCallback`) | No |
| Local development with Playwright (`PlaywrightLocalCallback`) | No |
| Cloud/headless SSO (`AgentCoreBrowserCallback`) | Yes |
| Browser session persistence via `AgentCoreBrowserSessionProvider` | Yes |
| Browser session persistence via `S3SessionProvider` or `LocalFileSessionProvider` | No |


## Minimal setup for local development

For local development, you need Cognito, S3, and an AWS KMS key. AgentCore is optional.

```bash
# 1. Create Cognito User Pool, S3 bucket, and KMS key (sections 1, 3, 4 above)

# 2. Run the sample
cd /path/to/NovaActAuthPy
.venv/bin/python -m samples.sso_authenticate --callback=localhost --store=s3
```

This uses:
- `LocalhostCallback` - opens the system browser for SSO
- `S3TokenStore` - saves tokens to S3 with SSE-KMS encryption
- Requires S3 bucket and AWS KMS key (sections 3 and 4)


## Full setup

With S3 persistence and AgentCore Browser:

1. Create the AWS KMS key (section 4)
2. Create the S3 bucket with SSE-KMS (section 3)
3. Create the Cognito User Pool (section 1)
4. Optionally create a Verified Permissions policy store (section 2)
5. Set up AgentCore Browser (section 5)
6. Configure IAM role with permissions for S3, AWS KMS, Verified Permissions, and AgentCore
6. Set environment variables:

```bash
# Cognito
export AGENT_AUTH_COGNITO_DOMAIN='{prefix}.auth.{region}.amazoncognito.com'
export AGENT_AUTH_COGNITO_CLIENT_ID='{client-id}'
export AGENT_AUTH_IDP_NAME='{provider-name}'

# Storage
export AGENT_AUTH_TOKEN_STORE='s3'
export AGENT_AUTH_S3_BUCKET='{bucket}'
export AGENT_AUTH_S3_KMS_KEY='alias/nova-act-sessions'
export AGENT_AUTH_REGION='us-east-1'
```
