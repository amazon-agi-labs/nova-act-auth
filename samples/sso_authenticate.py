"""Sample: SSO authentication via Cognito PKCE OAuth2 flow.

Demonstrates the authenticate() function with different callback
strategies, token refresh, and token persistence backends.

Callback strategies:

  localhost:    Opens the system browser; a local HTTP server catches
                the OAuth redirect. Uses the existing browser profile,
                so saved passwords and cookies are available.

  playwright:   Launches a fresh Playwright Chromium (incognito-like).
                No existing cookies or saved passwords. The redirect is
                intercepted directly via Playwright - no localhost
                server needed.

  agentcore:    Opens an AgentCore Browser session. The user completes
                SSO in the AWS console. Requires AWS
                credentials and --region.

Token persistence:

  s3:     Tokens saved to s3://{bucket}/tokens/{profile}.json
          with SSE-KMS encryption. Requires --s3_bucket.

Prerequisites:
    - Cognito App Client with http://localhost:8976/callback and
      https://auth.callback.internal/callback registered as
      allowed callback URLs
    - For S3 persistence: AWS credentials + an S3 bucket
    - Environment variables set (see samples/.env)

Usage:
    source samples/.env
    python -m samples.sso_authenticate
    python -m samples.sso_authenticate --callback=playwright
    python -m samples.sso_authenticate --callback=agentcore
    python -m samples.sso_authenticate --store=s3
    python -m samples.sso_authenticate --purge
    python -m samples.sso_authenticate --refresh
"""

import logging
import os

import fire

from nova_act_auth import (
    AuthConfig,
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
# CLI
# ---------------------------------------------------------------------------


def _log_result(result: AuthResult, session_key: str) -> None:
    _logger.info("  Email:         %s", result.user_info.get("email", "N/A"))
    _logger.info("  Subject:       %s", result.user_info.get("sub", "N/A"))
    _logger.info("  Name:          %s", result.user_info.get("name", "N/A"))
    _logger.info("  Expires at:    %s", result.expires_at)
    _logger.info("  Session key:   %s", session_key)
    _logger.info("  Access token:  %s", "present" if result.access_token else "not present")
    _logger.info("  Refresh token: %s", "present" if result.refresh_token else "not returned")


def main(
    callback: str = os.getenv("AGENT_AUTH_CALLBACK", "localhost"),
    profile: str = os.getenv("AGENT_AUTH_PROFILE", "default"),
    purge: bool = False,
    refresh: bool = False,
    store: str = os.getenv("AGENT_AUTH_TOKEN_STORE", "s3"),
    region: str = os.getenv("AGENT_AUTH_REGION", "us-east-1"),
    s3_bucket: str | None = os.getenv("AGENT_AUTH_S3_BUCKET"),
    s3_kms_key: str = os.getenv("AGENT_AUTH_S3_KMS_KEY", ""),
) -> None:
    """SSO authentication via Cognito PKCE OAuth2 flow.

    All args (except purge/refresh) can be set via environment variables.
    CLI args override env vars. See samples/.env.

    Args:
        callback: Callback strategy - localhost, playwright, or agentcore.
        profile: Profile name used as the token storage key.
        purge: Delete saved tokens and force re-authentication.
        refresh: Force a token refresh using the cached refresh token.
        store: Token persistence backend - s3.
        region: AWS region for AgentCore Browser and S3.
        s3_bucket: S3 bucket name (required when store=s3).
        s3_kms_key: KMS key ID or alias for SSE-KMS encryption.
    """
    config = AuthConfig.from_env()
    key_builder = IdentitySessionKeyBuilder()

    # Build token store
    try:
        token_store = build_token_store(store, s3_bucket=s3_bucket, s3_kms_key=s3_kms_key, region=region)
    except ValueError as exc:
        _logger.error("%s", exc)
        return

    # Purge if requested
    if purge:
        token_key = token_store.load_session_key(profile) or profile
        token_store.delete(token_key)
        _logger.info("Purged saved tokens for profile '%s'.", profile)

    # Force refresh if requested
    if refresh:
        token_key = token_store.load_session_key(profile) or profile
        saved = token_store.load(token_key)
        if saved is None or not saved.refresh_token:
            _logger.error("No cached refresh token for profile '%s'. Run without --refresh first.", profile)
            return
        _logger.info("Forcing token refresh for profile '%s'...", profile)
        result = refresh_tokens(config, saved)
        session_key = key_builder.build_key(result, config)
        token_store.save(session_key, result)
        token_store.save_session_key(profile, session_key)
        _logger.info("=== Token refresh successful ===")
        _log_result(result, session_key)
        return

    # Authenticate (uses cache, refresh, or interactive SSO as needed)
    result = get_or_authenticate(
        config,
        profile=profile,
        token_store=token_store,
        strategy=CallbackStrategyType(callback),
        region=region,
        session_key_builder=key_builder,
    )

    _logger.info("=== Authentication successful ===")
    _log_result(result, token_store.load_session_key(profile) or profile)


if __name__ == "__main__":
    fire.Fire(main)
