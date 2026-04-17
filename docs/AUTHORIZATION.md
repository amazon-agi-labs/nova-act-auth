# Authorization

After authentication proves the user's identity, authorization decides whether that user is allowed to run the agent. The library provides an `AuthorizationPolicy` ABC and several built-in implementations. This guide covers four approaches that the library supports out of the box - from zero-infra to fully externalized Cedar policies.

These are not exhaustive. Other authorization backends - such as OPA (Open Policy Agent), OPAL, Casbin, Oso, or a custom service backed by your own database - can work equally well. The library provides an extensible `AuthorizationPolicy` ABC so you can integrate any authorization system (see [Writing a custom policy](#writing-a-custom-policy)).

All approaches follow the same pattern:

```python
from nova_act_auth import AuthConfig, get_or_authenticate

config = AuthConfig.from_env()
result = get_or_authenticate(config)

policy = ...  # one of the approaches below
policy.authorize(result)  # raises AuthorizationError if denied
```

## Comparison

| Approach | Extra infra | Policy changes require | Best for |
|----------|------------|------------------------|----------|
| [1. Allow all](#1-allow-all) | None | Code deploy | Development, single-user agents |
| [2. Email domain allowlist](#2-email-domain-allowlist) | None | Code deploy | Simple org-level gating |
| [3. Cognito groups](#3-cognito-groups) | None (groups in Cognito) | Cognito console | Role-based access |
| [4. Verified Permissions](#4-verified-permissions) | Verified Permissions policy store | Cedar policy update (no deploy) | Fine-grained, auditable, multi-agent |

## 1. Allow all

Permits every authenticated user. This is the default - if you don't configure a policy, all users who complete SSO can run the agent.

```python
from nova_act_auth import AllowAllPolicy

policy = AllowAllPolicy()
policy.authorize(result)  # always passes
```

When to use: development, demos, single-user agents, or when authentication alone is sufficient.

## 2. Email domain allowlist

Checks the user's email domain against a list. No additional AWS resources needed - the email claim comes from the Cognito ID token.

```python
from nova_act_auth import AllowedDomainsPolicy

policy = AllowedDomainsPolicy(["company.com", "partner.org"])
policy.authorize(result)  # raises if email is not @company.com or @partner.org
```

Domain matching is case-insensitive. Raises `AuthorizationError` if the email claim is missing or the domain is not in the list.

When to use: restrict agent access to your organization's email domains without any infra setup.

## 3. Cognito groups

Cognito User Pools support groups. When a user belongs to a group, the `cognito:groups` claim is included in the ID token automatically. No extra infrastructure - groups are managed in the Cognito console or via the `AdminAddUserToGroup` API.

This is not a built-in policy - implement it by extending `AuthorizationPolicy`:

```python
from nova_act_auth import AuthorizationPolicy, AuthResult
from nova_act_auth.errors import AuthorizationError

class CognitoGroupPolicy(AuthorizationPolicy):
    def __init__(self, required_group: str) -> None:
        self._required_group = required_group

    def authorize(self, result: AuthResult) -> None:
        groups = result.user_info.get("cognito:groups", [])
        if self._required_group not in groups:
            raise AuthorizationError(
                f"User is not in the '{self._required_group}' group."
            )
```

Usage:

```python
policy = CognitoGroupPolicy("AgentOperators")
policy.authorize(result)
```

### Setting up groups

```bash
# Create a group
aws cognito-idp create-group \
  --user-pool-id us-east-1_abc123 \
  --group-name AgentOperators

# Add a user to the group
aws cognito-idp admin-add-user-to-group \
  --user-pool-id us-east-1_abc123 \
  --username alice \
  --group-name AgentOperators
```

When to use: role-based access (operators vs viewers, team-level gating). Changes take effect on next token refresh - no code deploy needed.

AWS docs:
- [Adding groups to a user pool](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html)

## 4. Verified Permissions

Amazon Verified Permissions is a managed authorization service that uses the Cedar policy language. A reference implementation (`VerifiedPermissionsPolicy`) is provided in `samples/sso_then_agent.py` that calls the `IsAuthorizedWithToken` API with the Cognito ID token. Cedar policies make the ALLOW/DENY decision.

Advantages over in-code policies:

- **Policy changes don't require code deploys** - update Cedar policies via the console or API.
- **Audit trail** - CloudTrail logs every authorization decision.
- **Centralized** - one policy store can serve multiple agents.
- **Token validation** - Verified Permissions validates the token signature and expiration automatically when a Cognito identity source is configured. Token revocation is not checked - a revoked token remains valid until its `exp` claim lapses ([source](https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_IsAuthorizedWithToken.html)).

### Minimum setup (least restrictive)

This creates a policy store that permits all authenticated users. The token must be valid (signed by Cognito, not expired), but no further restrictions are enforced. Customers add restrictive Cedar policies later.

```bash
REGION="us-east-1"
USER_POOL_ID="us-east-1_abc123"       # from Cognito setup
CLIENT_ID="your-app-client-id"         # from Cognito setup

# 1. Create policy store (no schema validation - simplest start)
POLICY_STORE_ID=$(aws verifiedpermissions create-policy-store \
  --validation-settings "mode=OFF" \
  --description "Agent authorization" \
  --region "${REGION}" \
  --query 'policyStoreId' --output text)
echo "Policy store: ${POLICY_STORE_ID}"

# 2. Connect Cognito as identity source
aws verifiedpermissions create-identity-source \
  --policy-store-id "${POLICY_STORE_ID}" \
  --principal-entity-type "Agent::User" \
  --configuration '{
    "cognitoUserPoolConfiguration": {
      "userPoolArn": "arn:aws:cognito-idp:'${REGION}':'$(aws sts get-caller-identity --query Account --output text)':userpool/'${USER_POOL_ID}'",
      "clientIds": ["'${CLIENT_ID}'"],
      "groupConfiguration": {
        "groupEntityType": "Agent::UserGroup"
      }
    }
  }' \
  --region "${REGION}"

# 3. Create permit-all policy (least restrictive default)
aws verifiedpermissions create-policy \
  --policy-store-id "${POLICY_STORE_ID}" \
  --definition '{
    "static": {
      "description": "Permit all authenticated users (default - add restrictive policies as needed)",
      "statement": "permit(principal, action, resource);"
    }
  }' \
  --region "${REGION}"

echo "Done. Policy store ID: ${POLICY_STORE_ID}"
```

That's three commands. The identity source handles token validation, and the single `permit(principal, action, resource);` policy allows all authenticated users through.

### Using in code

```python
# VerifiedPermissionsPolicy is defined in samples/sso_then_agent.py
policy = VerifiedPermissionsPolicy(
    policy_store_id="PSEXAMPLEabcdefg111111",
    region="us-east-1",
)
policy.authorize(result)
```

Default Cedar entity types: `Agent::Action::"RunAgent"` and `Agent::Resource::"agent"`. Override with the `action`, `resource`, and `namespace` parameters.

### Adding restrictions

Once the baseline is in place, add Cedar policies to restrict access. The permit-all policy can stay - Cedar evaluates all policies and a single `forbid` overrides any `permit`.

#### Restrict to a Cognito group

```cedar
// Remove the permit-all policy first, or add a forbid for non-members.
permit (
    principal in Agent::UserGroup::"us-east-1_abc123|AgentOperators",
    action,
    resource
);
```

#### Restrict by email domain

```cedar
permit (
    principal,
    action,
    resource
) when {
    principal has email &&
    principal.email like "*@company.com"
};
```

#### Per-agent authorization

Model each agent as a separate resource:

```python
policy = VerifiedPermissionsPolicy(
    policy_store_id="PSEXAMPLEabcdefg111111",
    action="RunAgent",
    resource="expense-agent",  # or "outlook-agent", etc.
)
```

```cedar
permit (
    principal in Agent::UserGroup::"us-east-1_abc123|FinanceTeam",
    action == Agent::Action::"RunAgent",
    resource == Agent::Resource::"expense-agent"
);
```

#### Deny unverified emails

```cedar
forbid (
    principal,
    action,
    resource
) unless {
    principal has email_verified &&
    principal.email_verified == true
};
```

### Adding a schema (optional, recommended for production)

A schema enables policy validation - Verified Permissions rejects policies that reference undefined attributes or entity types. This is optional for getting started but recommended before going to production.

```bash
# Create schema.json
cat > schema.json << 'SCHEMA'
{
  "cedarJson": "{\"Agent\":{\"entityTypes\":{\"User\":{\"memberOfTypes\":[\"UserGroup\"],\"shape\":{\"type\":\"Record\",\"attributes\":{\"email\":{\"type\":\"String\",\"required\":false},\"email_verified\":{\"type\":\"Boolean\",\"required\":false},\"cognito:username\":{\"type\":\"String\",\"required\":false}}}},\"UserGroup\":{},\"Resource\":{\"shape\":{\"type\":\"Record\",\"attributes\":{}}}},\"actions\":{\"RunAgent\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Resource\"]}}}}}"
}
SCHEMA

# Upload (update validation mode to STRICT)
aws verifiedpermissions put-schema \
  --policy-store-id "${POLICY_STORE_ID}" \
  --definition file://schema.json \
  --region "${REGION}"

aws verifiedpermissions update-policy-store \
  --policy-store-id "${POLICY_STORE_ID}" \
  --validation-settings "mode=STRICT" \
  --region "${REGION}"
```

### IAM permissions

The agent's IAM role needs:

```json
{
  "Effect": "Allow",
  "Action": "verifiedpermissions:IsAuthorizedWithToken",
  "Resource": "arn:aws:verifiedpermissions:{region}:{account}:policy-store/{policy-store-id}"
}
```

### Limits

| Resource | Default | Adjustable |
|----------|---------|------------|
| Policy stores per region | 30,000 | Yes |
| Identity sources per policy store | 1 | No |
| `IsAuthorizedWithToken` TPS | 200 | Yes |

### AWS documentation

- [What is Amazon Verified Permissions?](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html)
- [Working with Cognito identity sources](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/identity-sources-cognito.html)
- [Mapping Cognito tokens to Cedar schema](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/cognito-map-token-to-schema.html)
- [Cedar policy language reference](https://docs.cedarpolicy.com/)
- [Verified Permissions quotas](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/quotas.html)

## Writing a custom policy

All built-in policies extend `AuthorizationPolicy`. To implement custom logic (e.g., calling an external service, checking a database, combining multiple checks):

```python
from nova_act_auth import AuthorizationPolicy, AuthResult
from nova_act_auth.errors import AuthorizationError

class MyPolicy(AuthorizationPolicy):
    def authorize(self, result: AuthResult) -> None:
        # result.id_token    - Cognito ID token (JWT)
        # result.user_info   - decoded claims (email, sub, cognito:groups, etc.)
        if not self._is_allowed(result):
            raise AuthorizationError("Not authorized.")
```

The `authorize` method should either return `None` (authorized) or raise `AuthorizationError` (denied). The `result.user_info` dict contains the decoded ID token claims - the same data available in Cedar policies.

### Composing policies

Combine multiple policies with a simple wrapper:

```python
class AllOfPolicy(AuthorizationPolicy):
    def __init__(self, *policies: AuthorizationPolicy) -> None:
        self._policies = policies

    def authorize(self, result: AuthResult) -> None:
        for policy in self._policies:
            policy.authorize(result)  # first failure raises

policy = AllOfPolicy(
    AllowedDomainsPolicy(["company.com"]),
    CognitoGroupPolicy("AgentOperators"),
)
```
