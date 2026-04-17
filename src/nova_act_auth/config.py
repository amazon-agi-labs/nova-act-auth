"""SSO configuration and result types."""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

_logger = logging.getLogger(__name__)


class CallbackStrategyType(StrEnum):
    """Named callback strategies for ``get_or_authenticate()``.

    Each value corresponds to a ``CallbackStrategy`` implementation:

    - ``LOCALHOST`` - system browser + localhost HTTP server
    - ``PLAYWRIGHT`` - fresh Playwright Chromium (incognito-like)
    - ``AGENTCORE`` - AgentCore Browser (user completes SSO in the AWS console)
    """

    LOCALHOST = "localhost"
    PLAYWRIGHT = "playwright"
    AGENTCORE = "agentcore"


@dataclass(frozen=True)
class AuthConfig:
    """Configuration for SSO authentication via Cognito.

    SSO settings only. Session persistence is handled by the
    NovaAct SDK's ``BrowserSessionProvider`` implementations.

    Configuration priority: explicit constructor args > environment
    variables (via ``from_env()``) > defaults.
    """

    cognito_domain: str
    """Cognito Hosted UI domain.

    Example: ``my-app.auth.us-east-1.amazoncognito.com``

    Env: ``AGENT_AUTH_COGNITO_DOMAIN``
    """

    cognito_client_id: str
    """Cognito App Client ID (public client, no secret).

    A single App Client can have multiple federated IdPs enabled.
    Which IdPs are available is configured on the App Client in the
    Cognito console or CDK, not here. See ``identity_provider`` to
    control IdP selection at login time.

    Env: ``AGENT_AUTH_COGNITO_CLIENT_ID``
    """

    identity_provider: str | None = None
    """If set, skip the Hosted UI IdP selector and redirect
    straight to this IdP. The value is the provider name you
    assigned when creating the identity provider in Cognito.

    Maps to the Cognito ``idp_identifier`` query parameter,
    which only accepts a single value. This is intentionally
    a single string, not a list:

    - ``None`` (default) - Cognito shows the Hosted UI IdP
      selector with all IdPs enabled on the App Client.
    - A string - Cognito skips the selector and redirects
      directly to the named IdP.

    To restrict which IdPs appear in the selector, configure
    the allowed IdPs on the Cognito App Client itself.

    Env: ``AGENT_AUTH_IDP_NAME``
    """

    scopes: tuple[str, ...] = ("openid", "email", "profile")
    """OAuth scopes to request during the authorize step."""

    callback_port: int = 8976
    """Preferred localhost port for the OAuth callback server.
    Falls back to a random port if unavailable.

    Env: ``AGENT_AUTH_CALLBACK_PORT``
    """

    callback_timeout: int = 120
    """Seconds to wait for the user to complete SSO in the browser.

    Env: ``AGENT_AUTH_CALLBACK_TIMEOUT``
    """

    @classmethod
    def from_env(cls) -> AuthConfig:
        """Create configuration from environment variables.

        Required environment variables:
            - ``AGENT_AUTH_COGNITO_DOMAIN``
            - ``AGENT_AUTH_COGNITO_CLIENT_ID``

        Raises:
            ValueError: If required environment variables are missing.
        """
        cognito_domain = os.environ.get("AGENT_AUTH_COGNITO_DOMAIN", "")
        cognito_client_id = os.environ.get("AGENT_AUTH_COGNITO_CLIENT_ID", "")

        if not cognito_domain:
            raise ValueError(
                "AGENT_AUTH_COGNITO_DOMAIN environment variable is required. "
                "Set it to your Cognito Hosted UI domain "
                "(e.g., 'my-app.auth.us-east-1.amazoncognito.com')."
            )
        if not cognito_client_id:
            raise ValueError(
                "AGENT_AUTH_COGNITO_CLIENT_ID environment variable is required. Set it to your Cognito App Client ID."
            )

        return cls(
            cognito_domain=cognito_domain,
            cognito_client_id=cognito_client_id,
            identity_provider=os.environ.get("AGENT_AUTH_IDP_NAME"),
            callback_port=int(os.environ.get("AGENT_AUTH_CALLBACK_PORT", "8976")),
            callback_timeout=int(os.environ.get("AGENT_AUTH_CALLBACK_TIMEOUT", "120")),
        )


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthResult:
    """Result of a successful SSO authentication.

    Contains the Cognito JWT tokens and decoded user information.
    """

    access_token: str
    """Cognito access token (JWT).

    Pass this to ``get_workload_access_token_for_jwt()`` to
    obtain a Workload Access Token (WAT).
    """

    id_token: str
    """Cognito ID token (JWT).

    Contains user identity claims (sub, email, name, etc.).
    Decoded claims are available in ``user_info``.
    """

    refresh_token: str | None
    """Cognito refresh token.

    Used to obtain new access/ID tokens without re-authentication.
    ``None`` if refresh tokens are disabled on the Cognito App Client.
    """

    expires_at: datetime
    """UTC timestamp when the access token expires."""

    user_info: dict[str, Any]
    """Decoded claims from the ID token.

    Typical keys: ``sub``, ``email``, ``name``, ``cognito:groups``.
    """


# ---------------------------------------------------------------------------
# Session key builder
# ---------------------------------------------------------------------------


class SessionKeyBuilder(ABC):
    """Builds a session profile key from authentication context.

    The key is used by the NovaAct SDK's ``BrowserSessionProvider``
    to identify which stored session to load or save. Different
    implementations can produce keys suited to their domain -
    per-user, per-tenant, per-team, etc.

    Callers must provide their own implementation. See the samples for
    a reference implementation (``IdentitySessionKeyBuilder``).
    """

    @abstractmethod
    def build_key(self, auth_result: AuthResult, config: AuthConfig) -> str:
        """Build a session profile key from auth context.

        Args:
            auth_result: Result from ``authenticate()`` containing
                user identity claims.
            config: Auth config used for authentication.

        Returns:
            A string suitable for use as a session profile key.
        """
