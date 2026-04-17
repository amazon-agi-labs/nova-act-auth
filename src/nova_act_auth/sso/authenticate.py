"""Main SSO authentication orchestration.

Ties together PKCE generation, a callback strategy, and the
Cognito token exchange into ``get_or_authenticate()``,
``authenticate()``, and ``refresh_tokens()``.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

import requests
from authlib.common.security import generate_token
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from nova_act_auth.config import (
    AuthResult,
    CallbackStrategyType,
)
from nova_act_auth.errors import SSOTokenExchangeError
from nova_act_auth.sso.callback.agentcore import AgentCoreBrowserCallback
from nova_act_auth.sso.callback.localhost import LocalhostCallback
from nova_act_auth.sso.callback.playwright_local import PlaywrightLocalCallback

if TYPE_CHECKING:
    from nova_act_auth.config import AuthConfig, SessionKeyBuilder
    from nova_act_auth.sso.callback.strategy import CallbackStrategy
    from nova_act_auth.token_store import TokenStore

_logger = logging.getLogger(__name__)


def authenticate(
    config: AuthConfig,
    callback: CallbackStrategy | None = None,
) -> AuthResult:
    """Perform SSO authentication via Cognito with PKCE.

    Orchestrates the full OAuth2 Authorization Code flow with PKCE:

    1. Generate PKCE code_verifier and code_challenge.
    2. Generate a random state parameter for CSRF protection.
    3. Initialize the callback strategy (start server, etc.).
    4. Build the Cognito authorize URL.
    5. Present the URL to the user and wait for the callback.
    6. Exchange the code for JWT tokens at the Cognito token endpoint.

    Args:
        config: SSO configuration (Cognito domain, client ID, etc.).
        callback: Strategy for receiving the OAuth callback. Defaults
            to ``LocalhostCallback`` which opens the system browser
            and listens on a local port. Pass
            ``AgentCoreBrowserCallback(page=...)`` to use a Playwright
            page instead.

    Returns:
        ``AuthResult`` containing access and ID tokens, decoded
        user info, and expiration.

    Raises:
        SSOTimeoutError: User did not complete SSO in time.
        SSOBrowserError: System browser could not be opened (localhost mode).
        SSOInvalidStateError: State parameter mismatch (CSRF).
        SSOTokenExchangeError: Token exchange with Cognito failed.
        SSOError: Other SSO failures.
    """
    if callback is None:
        callback = LocalhostCallback(port=config.callback_port)

    # 1. Generate PKCE pair
    code_verifier, code_challenge = _generate_pkce_pair()
    _logger.debug("Generated PKCE code challenge")

    # 2. Generate state for CSRF protection
    state = uuid.uuid4().hex
    _logger.debug("Generated OAuth state parameter")

    # 3. Initialize callback strategy (e.g., start localhost server)
    callback.start(expected_state=state)

    try:
        redirect_uri = callback.redirect_uri

        # 4. Build Cognito authorize URL (RFC 6749 Section 4.1.1 + RFC 7636 Section 4.3)
        authorize_url = prepare_grant_uri(
            f"https://{config.cognito_domain}/oauth2/authorize",
            client_id=config.cognito_client_id,
            response_type="code",
            redirect_uri=redirect_uri,
            scope=config.scopes,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            identity_provider=config.identity_provider,
        )

        _logger.info("Starting SSO login (timeout: %ds)", config.callback_timeout)

        # 5. Present URL and wait for callback
        authorization_code = callback.wait_for_code(
            authorize_url=authorize_url,
            timeout=config.callback_timeout,
        )
    finally:
        callback.cleanup()

    # 6. Exchange code for tokens
    result = _exchange_code_for_tokens(
        cognito_domain=config.cognito_domain,
        client_id=config.cognito_client_id,
        code=authorization_code,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )

    _logger.info("SSO authentication successful")
    return result


def refresh_tokens(config: AuthConfig, auth_result: AuthResult) -> AuthResult:
    """Refresh expired Cognito tokens using the stored refresh token.

    Calls the Cognito ``/oauth2/token`` endpoint with
    ``grant_type=refresh_token`` to obtain fresh access and ID
    tokens without requiring user interaction.

    Args:
        config: Auth config with cognito_domain and cognito_client_id.
        auth_result: Previous auth result containing a refresh token.

    Returns:
        New ``AuthResult`` with fresh access/ID tokens. If the Cognito
        User Pool client has refresh token rotation enabled, the returned
        ``AuthResult`` contains the new refresh token issued by Cognito.
        Otherwise the original refresh token is carried forward.
        ``user_info`` is re-decoded from the new ID token.

    Raises:
        SSOTokenExchangeError: If the refresh fails (e.g., token
            revoked or expired).
        ValueError: If ``auth_result`` has no refresh token.
    """
    if not auth_result.refresh_token:
        msg = "Cannot refresh: auth_result has no refresh token."
        raise ValueError(msg)

    _logger.info("Refreshing Cognito tokens")
    return _exchange_refresh_token(
        cognito_domain=config.cognito_domain,
        client_id=config.cognito_client_id,
        refresh_token=auth_result.refresh_token,
    )


def _resolve_strategy(
    config: AuthConfig,
    strategy: CallbackStrategyType | str,
    region: str,
) -> AuthResult:
    """Resolve a named strategy and run interactive SSO."""
    try:
        strategy = CallbackStrategyType(strategy)
    except ValueError:
        valid = ", ".join(s.value for s in CallbackStrategyType)
        msg = f"Unknown callback strategy '{strategy}'. Must be one of: {valid}"
        raise ValueError(msg) from None

    if strategy is CallbackStrategyType.AGENTCORE:
        return _authenticate_agentcore(config, region)
    elif strategy is CallbackStrategyType.PLAYWRIGHT:
        return authenticate(config, callback=PlaywrightLocalCallback())
    else:
        return authenticate(config, callback=LocalhostCallback(port=config.callback_port))


def get_or_authenticate(
    config: AuthConfig,
    *,
    profile: str = "default",
    token_store: TokenStore,
    strategy: CallbackStrategyType | str = CallbackStrategyType.LOCALHOST,
    region: str = "us-east-1",
    session_key_builder: SessionKeyBuilder,
) -> AuthResult:
    """Return cached tokens if valid, refresh if expired, or run SSO.

    High-level function that encapsulates the full authentication
    lifecycle:

    1. Look up cached tokens for ``profile``.
    2. If valid (not expired), return immediately.
    3. If expired but a refresh token is present, attempt silent refresh.
    4. If refresh fails or no cached tokens exist, run interactive SSO.
    5. Save the resulting tokens and update the profile mapping.

    Args:
        config: SSO configuration (Cognito domain, client ID, etc.).
        profile: Short, caller-chosen name for this authentication
            context (e.g., ``"default"``, ``"work"``). Used to look
            up the identity-derived session key saved after the last
            successful authentication. If no mapping exists yet, the
            profile name itself is used as a fallback storage key.
            In shared-bucket deployments where multiple users write
            to the same store, use a name unique per user (e.g., the
            user's email address) to avoid overwriting each other's
            mappings. Generic names like ``"default"`` are only safe
            in single-user deployments.
        token_store: Backend for saving/loading tokens and profile
            mappings. All state (tokens and the profile-to-session-key
            index) is stored through this object.
        strategy: Callback strategy for interactive SSO. A
            ``CallbackStrategyType`` enum value or its string
            equivalent (e.g., ``"localhost"``). Only used when
            cached/refreshed tokens are unavailable.
        region: AWS region for AgentCore Browser and S3.
        session_key_builder: Derives the token storage key from the
            authenticated user's identity and the auth config. Controls
            how tokens are namespaced in the store (e.g., by user,
            tenant, or environment). See the samples for a reference
            implementation (``IdentitySessionKeyBuilder``).

    Returns:
        ``AuthResult`` with valid tokens - either cached, refreshed,
        or freshly obtained via SSO.

    Raises:
        SSOTimeoutError: User did not complete SSO in time.
        SSOTokenExchangeError: Token exchange or refresh failed.
    """
    token_key = token_store.load_session_key(profile) or profile

    # 1. Try cached tokens
    saved = token_store.load(token_key)
    if saved is not None and saved.expires_at > datetime.now(UTC):
        _logger.info("Restored cached tokens for profile '%s'", profile)
        return saved

    # 2. Try refresh
    if saved is not None and saved.refresh_token:
        _logger.info("Access token expired - attempting refresh...")
        try:
            refreshed = refresh_tokens(config, saved)
            session_key = session_key_builder.build_key(refreshed, config)
            token_store.save(session_key, refreshed)
            token_store.save_session_key(profile, session_key)
            _logger.info("Token refresh successful")
            return refreshed
        except SSOTokenExchangeError as exc:
            _logger.warning("Refresh failed (%s) - falling back to SSO", exc)
            token_store.delete(token_key)

    # 3. Full interactive SSO
    result = _resolve_strategy(config, strategy, region)
    session_key = session_key_builder.build_key(result, config)
    token_store.save(session_key, result)
    token_store.save_session_key(profile, session_key)
    _logger.info("Authentication successful, tokens saved for profile '%s'", profile)
    return result


def _authenticate_agentcore(config: AuthConfig, region: str) -> AuthResult:
    """Run SSO via AgentCore Browser with full lifecycle management."""
    from bedrock_agentcore.tools.browser_client import browser_session
    from playwright.sync_api import sync_playwright

    _logger.info("Starting AgentCore Browser session (region=%s)", region)
    _logger.info("Complete SSO via Live View in the AWS console.")

    with browser_session(region) as browser_client:
        ws_url, headers = browser_client.generate_ws_headers()
        with sync_playwright() as pw:
            browser = pw.chromium.connect_over_cdp(ws_url, headers=headers)
            context = browser.contexts[0] if browser.contexts else browser.new_context()
            page = context.new_page()
            try:
                return authenticate(config, callback=AgentCoreBrowserCallback(page=page))
            finally:
                with contextlib.suppress(Exception):
                    page.close()
                with contextlib.suppress(Exception):
                    browser.close()


# ---------------------------------------------------------------------------
# PKCE (RFC 7636)
# ---------------------------------------------------------------------------


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge pair.

    The code_verifier is a 48-character cryptographically random
    string. The code_challenge is ``BASE64URL(SHA256(code_verifier))``.

    Returns:
        Tuple of ``(code_verifier, code_challenge)``.
    """
    code_verifier: str = generate_token(48)
    code_challenge: str = create_s256_code_challenge(code_verifier)
    return code_verifier, code_challenge


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------

_TOKEN_ENDPOINT_TIMEOUT = 30  # seconds
_DEFAULT_TOKEN_LIFETIME = 3600  # seconds (RFC 6749 Section 5.1: fallback if expires_in is missing)


def _exchange_code_for_tokens(
    *,
    cognito_domain: str,
    client_id: str,
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> AuthResult:
    """Exchange an authorization code for Cognito JWT tokens.

    Uses ``OAuth2Session.fetch_token()`` to POST to
    ``https://{cognito_domain}/oauth2/token`` with the authorization
    code and PKCE code_verifier (RFC 6749 Section 4.1.3 + RFC 7636
    Section 4.5).

    Returns:
        ``AuthResult`` with access_token, id_token, refresh_token,
        expiration, and decoded user_info.

    Raises:
        SSOTokenExchangeError: If the token exchange fails.
    """
    token_url = f"https://{cognito_domain}/oauth2/token"

    session = OAuth2Session(
        client_id=client_id,
        token_endpoint_auth_method="none",  # noqa: S106
        default_timeout=_TOKEN_ENDPOINT_TIMEOUT,
    )

    try:
        data = session.fetch_token(
            token_url,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
        )
    except OAuthError as exc:
        raise SSOTokenExchangeError(f"Token exchange failed: {exc.error} - {exc.description}") from exc
    except requests.RequestException as exc:
        raise SSOTokenExchangeError(f"Could not reach Cognito token endpoint at {token_url}: {exc}") from exc

    access_token = data.get("access_token", "")
    id_token_raw = data.get("id_token", "")
    refresh_token = data.get("refresh_token")
    expires_in = data.get("expires_in", _DEFAULT_TOKEN_LIFETIME)

    if not access_token or not id_token_raw:
        raise SSOTokenExchangeError("Cognito token response is missing access_token or id_token.")

    user_info = _decode_jwt_claims(id_token_raw, cognito_domain=cognito_domain, client_id=client_id)
    expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)

    return AuthResult(
        access_token=access_token,
        id_token=id_token_raw,
        refresh_token=refresh_token,
        expires_at=expires_at,
        user_info=user_info,
    )


def _exchange_refresh_token(
    *,
    cognito_domain: str,
    client_id: str,
    refresh_token: str,
) -> AuthResult:
    """Exchange a refresh token for fresh Cognito JWT tokens.

    Uses ``OAuth2Session.refresh_token()`` to POST to
    ``https://{cognito_domain}/oauth2/token`` with
    ``grant_type=refresh_token`` (RFC 6749 Section 6).

    Returns:
        ``AuthResult`` with fresh access_token and id_token. If Cognito
        returns a new refresh_token (i.e., refresh token rotation is
        enabled on the User Pool client), the new token is used. Otherwise
        the original refresh_token is carried forward.

    Raises:
        SSOTokenExchangeError: If the token refresh fails.
    """
    token_url = f"https://{cognito_domain}/oauth2/token"

    session = OAuth2Session(
        client_id=client_id,
        token_endpoint_auth_method="none",  # noqa: S106
        default_timeout=_TOKEN_ENDPOINT_TIMEOUT,
    )

    try:
        data = session.refresh_token(
            token_url,
            refresh_token=refresh_token,
        )
    except OAuthError as exc:
        raise SSOTokenExchangeError(f"Token refresh failed: {exc.error} - {exc.description}") from exc
    except requests.RequestException as exc:
        raise SSOTokenExchangeError(f"Could not reach Cognito token endpoint at {token_url}: {exc}") from exc

    access_token = data.get("access_token", "")
    id_token_raw = data.get("id_token", "")
    expires_in = data.get("expires_in", _DEFAULT_TOKEN_LIFETIME)

    if not access_token or not id_token_raw:
        raise SSOTokenExchangeError("Cognito refresh response is missing access_token or id_token.")

    user_info = _decode_jwt_claims(id_token_raw, cognito_domain=cognito_domain, client_id=client_id)
    expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)

    _logger.info("Token refresh successful")
    # When refresh token rotation is enabled on the Cognito User Pool client,
    # Cognito returns a new refresh_token that replaces the old one. Capture it
    # so callers that persist AuthResult continue to have a valid refresh token.
    new_refresh_token = data.get("refresh_token") or refresh_token
    return AuthResult(
        access_token=access_token,
        id_token=id_token_raw,
        refresh_token=new_refresh_token,
        expires_at=expires_at,
        user_info=user_info,
    )


# Cognito ID token issuer format: https://cognito-idp.<Region>.amazonaws.com/<userPoolId>
# Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-id-token.html
_COGNITO_ISS_PATTERN = re.compile(r"^https://cognito-idp\.([a-z0-9-]+)\.amazonaws\.com/[a-zA-Z0-9_-]+$")


def _extract_region_from_domain(cognito_domain: str) -> str | None:
    """Extract the AWS region from a Cognito hosted UI domain.

    Example: ``my-app.auth.us-east-1.amazoncognito.com`` -> ``us-east-1``.
    """
    match = re.search(r"\.auth\.([a-z0-9-]+)\.amazoncognito\.com$", cognito_domain)
    return match.group(1) if match else None


def _peek_jwt_payload(token: str) -> dict[str, Any]:
    """Base64-decode the JWT payload without signature verification.

    Used only to extract ``iss`` for JWKS URL construction before
    full verification.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1]
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    decoded = base64.urlsafe_b64decode(payload)
    return cast("dict[str, Any]", json.loads(decoded))


def _fetch_jwks(jwks_url: str) -> str:
    """Fetch the JSON Web Key Set from the given URL."""
    response = requests.get(jwks_url, timeout=10)
    response.raise_for_status()
    return response.text


def _decode_jwt_claims(token: str, *, cognito_domain: str, client_id: str) -> dict[str, Any]:
    """Decode and verify the ID token JWT using Cognito's JWKS.

    1. Peeks at the unverified payload to extract ``iss``.
    2. Validates that ``iss`` matches the Cognito issuer format and
       that the region matches ``cognito_domain``.
    3. Fetches the JWKS from ``{iss}/.well-known/jwks.json``.
    4. Verifies the signature with ``authlib.jose.jwt.decode()``.
    5. Validates ``iss``, ``aud``, and ``exp`` claims.

    Security note: signature verification proves the token was issued by
    Cognito, not that the claims within it are accurate. The values of
    identity claims (``email``, ``sub``, ``cognito:groups``) originate from
    the federated identity provider. A compromised upstream IdP can inject
    arbitrary claim values; this library cannot detect that. Downstream
    authorization policies should be aware of this trust boundary.

    Raises:
        SSOTokenExchangeError: If verification or claim validation fails.
    """
    try:
        # 1. Peek at unverified payload to get iss
        unverified = _peek_jwt_payload(token)
        iss = unverified.get("iss", "")

        # 2. Validate issuer format
        iss_match = _COGNITO_ISS_PATTERN.match(iss)
        if not iss_match:
            raise SSOTokenExchangeError(f"ID token issuer '{iss}' does not match expected Cognito format.")

        # 3. Validate region matches cognito_domain
        iss_region = iss_match.group(1)
        domain_region = _extract_region_from_domain(cognito_domain)
        if domain_region and iss_region != domain_region:
            raise SSOTokenExchangeError(
                f"ID token issuer region '{iss_region}' does not match cognito_domain region '{domain_region}'."
            )

        # 4. Fetch JWKS
        jwks_url = f"{iss}/.well-known/jwks.json"
        jwks_raw = _fetch_jwks(jwks_url)
        jwks = json.loads(jwks_raw)

        # 5. Verify signature and decode
        # JWT claim validation per RFC 7519 Sections 4.1.1-4.1.4
        # https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
        # Cognito ID token specifics per OpenID Connect Core Section 3.1.3.7
        # https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        jwt_handler = JsonWebToken(["RS256"])
        claims = jwt_handler.decode(
            token,
            key=jwks,
            claims_options={
                "iss": {"essential": True, "value": iss},
                "aud": {"essential": True, "value": client_id},
            },
        )

        # 6. Validate claims (exp, iss, aud)
        # No clock-skew leeway is applied because _decode_jwt_claims() is only
        # called immediately after token receipt from Cognito - never on cached
        # tokens. Clock drift between the library host and Cognito is negligible
        # in this context. Cached token expiry is checked separately in
        # get_or_authenticate() via AuthResult.expires_at.
        claims.validate()

        return dict(claims)
    except SSOTokenExchangeError:
        raise
    except JoseError as exc:
        raise SSOTokenExchangeError(f"ID token verification failed: {exc}") from exc
    except Exception as exc:
        raise SSOTokenExchangeError(f"Failed to verify ID token: {exc}") from exc
