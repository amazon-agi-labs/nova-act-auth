"""Sample: SSO identity gate, then agent navigates to a web app.

Demonstrates the two SSO use cases together:

  1. Identity gate - Cognito SSO via the library proves who the user
     is and authorizes the agent to run.
  2. Agent accessing a web app - NovaAct navigates to the starting
     page. If saved session cookies are present, the agent may land
     in the app without a login prompt. Otherwise, the agent requests
     a human UI takeover so the user can log in manually.

The SDK's S3SessionProvider persists browser state (cookies,
localStorage) between runs. On subsequent runs, saved IdP cookies
may skip the login entirely.

Authorization policies (optional):

  allow-all:      Permits all authenticated users (default).
  domain:         Checks email domain against an allowlist.
  cognito-group:  Checks Cognito group membership via ID token claims.
  avp:            Delegates to Amazon Verified Permissions (Cedar policies).

Prerequisites:
    - nova-act SDK installed with S3SessionProvider
    - Cognito App Client with callback URLs registered
    - AWS credentials configured
    - Environment variables set (see samples/.env)

Usage:
    source samples/.env
    python -m samples.sso_then_agent --starting_page=https://example.com
    python -m samples.sso_then_agent --starting_page=https://app.example.com --callback=agentcore
    python -m samples.sso_then_agent --starting_page=https://example.com --profile=alice
    python -m samples.sso_then_agent --starting_page=https://example.com --skip_sso
    python -m samples.sso_then_agent --starting_page=https://example.com --policy=cognito-group --group=AgentOperators
    python -m samples.sso_then_agent --starting_page=https://example.com --policy=domain --domains=company.com
    python -m samples.sso_then_agent --starting_page=https://example.com --refresh
"""

import logging
import os
import sys
from typing import Any

import fire

from nova_act_auth import (
    AllowAllPolicy,
    AllowedDomainsPolicy,
    AuthConfig,
    AuthorizationError,
    AuthorizationPolicy,
    AuthResult,
    CallbackStrategyType,
    SessionKeyBuilder,
    build_token_store,
    get_or_authenticate,
    refresh_tokens,
)


class IdentitySessionKeyBuilder(SessionKeyBuilder):
    """Keys sessions by ``email/provider/client_id``.

    Reference implementation of ``SessionKeyBuilder``. Produces a
    hierarchical key from the authenticated user's email, the identity
    provider name, and the Cognito client ID. This prevents token
    collisions when the same user authenticates via different IdPs or
    against different Cognito App Clients.

    Example::

        builder = IdentitySessionKeyBuilder()
        key = builder.build_key(result, config)
        # "alice@company.com/corp-idp/YOUR_CLIENT_ID"
    """

    def build_key(self, auth_result: AuthResult, config: AuthConfig) -> str:
        email = auth_result.user_info["email"].lower().strip()
        provider = (config.identity_provider or "default").lower().strip()
        client_id = config.cognito_client_id.strip()
        return f"{email}/{provider}/{client_id}"


logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Example custom policies (extend AuthorizationPolicy for your own)
# ---------------------------------------------------------------------------


class CognitoGroupPolicy(AuthorizationPolicy):
    """Checks that the user belongs to a Cognito group.

    The ``cognito:groups`` claim is included in the ID token when the
    user is a member of one or more Cognito User Pool groups. No extra
    infrastructure needed - groups are managed in the Cognito console
    or via the ``AdminAddUserToGroup`` API.

    See AUTHORIZATION.md for setup instructions.
    """

    def __init__(self, required_group: str) -> None:
        self._required_group = required_group

    def authorize(self, result: AuthResult) -> None:
        groups = result.user_info.get("cognito:groups", [])
        if self._required_group not in groups:
            raise AuthorizationError(
                f"User is not a member of the '{self._required_group}' group. Current groups: {groups}"
            )
        _logger.info(
            "CognitoGroupPolicy: user authorized (member of '%s')",
            self._required_group,
        )


class VerifiedPermissionsPolicy(AuthorizationPolicy):
    """Delegates authorization to Amazon Verified Permissions.

    Passes the Cognito ID token to the ``IsAuthorizedWithToken`` API.
    Verified Permissions validates the token, maps claims to Cedar
    principal attributes, and evaluates Cedar policies.

    Requires a policy store with a Cognito identity source.
    See AUTHORIZATION.md for setup instructions (3 CLI commands).
    """

    def __init__(
        self,
        policy_store_id: str,
        *,
        region: str = "us-east-1",
        action: str = "RunAgent",
        resource: str = "agent",
        namespace: str = "Agent",
    ) -> None:
        self._policy_store_id = policy_store_id
        self._region = region
        self._action = action
        self._resource = resource
        self._namespace = namespace
        self._client: Any = None

    def _get_client(self) -> Any:
        import boto3

        if self._client is None:
            self._client = boto3.client("verifiedpermissions", region_name=self._region)
        return self._client

    def authorize(self, result: AuthResult) -> None:
        client = self._get_client()
        try:
            response = client.is_authorized_with_token(
                policyStoreId=self._policy_store_id,
                identityToken=result.id_token,
                action={
                    "actionType": f"{self._namespace}::Action",
                    "actionId": self._action,
                },
                resource={
                    "entityType": f"{self._namespace}::Resource",
                    "entityId": self._resource,
                },
            )
        except Exception as exc:
            raise AuthorizationError(f"Verified Permissions request failed: {exc}") from exc

        decision = response.get("decision", "DENY")
        if decision != "ALLOW":
            policies = response.get("determiningPolicies", [])
            errors = response.get("errors", [])
            parts = [f"Verified Permissions denied access (decision={decision})."]
            if policies:
                parts.append(f"Determining policies: {policies}")
            if errors:
                parts.append(f"Evaluation errors: {errors}")
            raise AuthorizationError(" ".join(parts))

        _logger.info(
            "VerifiedPermissionsPolicy: authorized (policy_store=%s)",
            self._policy_store_id,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_policy(
    policy: str,
    *,
    domains: str | None,
    group: str | None,
    policy_store_id: str | None,
    region: str,
) -> AllowAllPolicy | AllowedDomainsPolicy | CognitoGroupPolicy | VerifiedPermissionsPolicy:
    """Build an authorization policy from CLI args."""
    if policy == "allow-all":
        return AllowAllPolicy()
    if policy == "domain":
        if not domains:
            _logger.error("--domains is required for domain policy")
            sys.exit(1)
        return AllowedDomainsPolicy([d.strip() for d in domains.split(",")])
    if policy == "cognito-group":
        if not group:
            _logger.error("--group is required for cognito-group policy")
            sys.exit(1)
        return CognitoGroupPolicy(group)
    if policy == "avp":
        if not policy_store_id:
            _logger.error("--policy_store_id is required for avp policy")
            sys.exit(1)
        return VerifiedPermissionsPolicy(policy_store_id, region=region)
    _logger.error("Unknown policy: %s (choose: allow-all, domain, cognito-group, avp)", policy)
    sys.exit(1)


def main(
    starting_page: str,
    callback: str = os.getenv("AGENT_AUTH_CALLBACK", "playwright"),
    profile: str = os.getenv("AGENT_AUTH_PROFILE", "default"),
    purge: bool = False,
    refresh: bool = False,
    skip_sso: bool = False,
    store: str = os.getenv("AGENT_AUTH_TOKEN_STORE", "s3"),
    region: str = os.getenv("AGENT_AUTH_REGION", "us-east-1"),
    s3_bucket: str = os.getenv("AGENT_AUTH_S3_BUCKET", ""),
    s3_kms_key: str = os.getenv("AGENT_AUTH_S3_KMS_KEY", ""),
    headless: bool = False,
    policy: str = "allow-all",
    domains: str | None = None,
    group: str | None = None,
    policy_store_id: str | None = os.getenv("AGENT_AUTH_AVP_POLICY_STORE_ID"),
) -> None:
    """SSO identity gate, then NovaAct agent navigates to a web app.

    All args (except skip_sso, refresh, and headless) can be set via
    environment variables. CLI args override env vars. See samples/.env.

    Args:
        starting_page: URL the agent navigates to after SSO.
        callback: SSO callback strategy - localhost, playwright, or agentcore.
        profile: Profile name for both SSO tokens and SDK session storage.
        purge: Delete saved tokens and force re-authentication.
        refresh: Force a token refresh using the cached refresh token.
        skip_sso: Skip the SSO identity gate and go straight to the agent.
        store: Token persistence backend - s3.
        region: AWS region for AgentCore Browser and S3.
        s3_bucket: S3 bucket for SDK session persistence and token storage.
        s3_kms_key: KMS key for SSE-KMS encryption.
        headless: Run the agent browser without a visible window.
        policy: Authorization policy - allow-all, domain, cognito-group, or avp.
        domains: Comma-separated allowed email domains (for domain policy).
        group: Required Cognito group name (for cognito-group policy).
        policy_store_id: AVP policy store ID (for avp policy).
    """
    if not starting_page:
        _logger.error("--starting_page is required")
        sys.exit(1)

    from nova_act import NovaAct, S3SessionProvider, workflow
    from nova_act.tools.human.interface.human_input_callback import (
        ApprovalResponse,
        HumanInputCallbacksBase,
        UiTakeoverResponse,
    )

    class _ConsoleHumanInputCallbacks(HumanInputCallbacksBase):
        """Human-in-the-loop callbacks for console-based interaction."""

        def approve(self, message: str) -> ApprovalResponse:
            raise NotImplementedError()

        def ui_takeover(self, message: str) -> UiTakeoverResponse:
            _logger.info("--- Human takeover requested ---")
            _logger.info("    %s", message)
            _logger.info("    Complete the action in the browser, then press Enter.")
            input("    Press Enter when done: ")
            return UiTakeoverResponse.COMPLETE

    # ----- Step 1: SSO identity gate -----

    if not skip_sso:
        config = AuthConfig.from_env()

        # Build token store
        try:
            token_store = build_token_store(
                store,
                s3_bucket=s3_bucket or None,
                s3_kms_key=s3_kms_key or None,
                region=region,
            )
        except ValueError as exc:
            _logger.error("%s", exc)
            sys.exit(1)

        # Purge if requested
        if purge:
            token_key = token_store.load_session_key(profile) or profile
            token_store.delete(token_key)
            _logger.info("Purged saved tokens for profile '%s'.", profile)

        key_builder = IdentitySessionKeyBuilder()

        # Force refresh if requested
        if refresh:
            token_key = token_store.load_session_key(profile) or profile
            saved = token_store.load(token_key)
            if saved is None or not saved.refresh_token:
                _logger.error("No cached refresh token for profile '%s'. Run without --refresh first.", profile)
                sys.exit(1)
            _logger.info("Forcing token refresh for profile '%s'...", profile)
            refreshed = refresh_tokens(config, saved)
            session_key = key_builder.build_key(refreshed, config)
            token_store.save(session_key, refreshed)
            token_store.save_session_key(profile, session_key)
            _logger.info("Token refresh successful")
            result = refreshed
        else:
            result = get_or_authenticate(
                config,
                profile=profile,
                token_store=token_store,
                strategy=CallbackStrategyType(callback),
                region=region,
                session_key_builder=key_builder,
            )

        # Authorization check
        authz_policy = _build_policy(
            policy,
            domains=domains,
            group=group,
            policy_store_id=policy_store_id,
            region=region,
        )
        try:
            authz_policy.authorize(result)
            _logger.info("Authorization passed (%s)", policy)
        except AuthorizationError as exc:
            _logger.error("Authorization denied: %s", exc)
            sys.exit(1)

        # Use the session key as the SDK profile so SSO identity
        # and browser state are keyed the same way.
        profile = token_store.load_session_key(profile) or profile
    else:
        _logger.info("SSO skipped (--skip_sso). No identity verification.")
        _logger.info("Using fallback profile: %s", profile)

    # ----- Step 2: NovaAct agent with session persistence -----

    _logger.info("Starting NovaAct agent...")

    session_provider = S3SessionProvider(
        bucket=s3_bucket,
        profile=profile,
        kms_key_id=s3_kms_key,
        region=region,
        restore_local_storage=True,
    )

    # Check if we have a saved session
    existing_state = session_provider.load_storage_state()
    if existing_state:
        cookie_count = len(existing_state.get("cookies", []))
        origin_count = len(existing_state.get("origins", []))
        _logger.info("Restoring session from S3: %d cookies, %d origins", cookie_count, origin_count)
    else:
        _logger.info("No saved session found in S3 - starting fresh.")
        _logger.info("The agent will pause for you to log in manually if needed.")

    @workflow(
        nova_act_api_key=os.getenv("NOVA_ACT_API_KEY"),
        model_id="nova-act-latest",
    )
    def run_agent() -> None:
        with NovaAct(
            starting_page=starting_page,
            browser_auth=session_provider,
            headless=headless,
            human_input_callbacks=_ConsoleHumanInputCallbacks(),
        ) as nova:
            nova.act(
                "Check whether you are logged in to the application. "
                "If you see a login page, invoke the human_UiTakeover "
                "tool so the user can log in manually."
            )

            nova.act("Describe the first 3 things you see on the page.")

        # On exit, the SDK automatically calls session_provider.save_session()
        # which persists browser state (cookies + localStorage) to S3.
        _logger.info("Session saved to s3://%s/nova-act-sessions/%s.json", s3_bucket, profile)

    run_agent()
    _logger.info("Done.")


if __name__ == "__main__":
    fire.Fire(main)
