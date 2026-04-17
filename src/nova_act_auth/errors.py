"""Error hierarchy for nova_act_auth."""

from __future__ import annotations


class AuthError(Exception):
    """Base error for all auth library errors.

    Attributes:
        retryable: Whether the caller should retry the operation.
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


# --- SSO errors ---


class SSOError(AuthError):
    """Base error for SSO authentication failures."""


class SSOTimeoutError(SSOError):
    """User did not complete SSO within the timeout period.

    Retryable. Increase ``AuthConfig.callback_timeout`` or set
    the ``AGENT_AUTH_CALLBACK_TIMEOUT`` environment variable.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=True)


class SSOBrowserError(SSOError):
    """Failed to open a browser for SSO login.

    Check that Playwright browsers are installed
    (``playwright install chromium``) or that a system browser
    is available.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=False)


class SSOInvalidStateError(SSOError):
    """OAuth state parameter mismatch.

    The callback did not originate from the current authorization
    request. This can happen if a stale browser tab completes an
    old SSO flow. Do not retry - start a new authentication.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=False)


class SSOTokenExchangeError(SSOError):
    """Failed to exchange authorization code for tokens.

    Common causes: expired authorization code (user took too long
    between SSO and code exchange), misconfigured Cognito App
    Client (wrong callback URL, missing scopes), or network
    issues reaching the Cognito token endpoint.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=False)


# --- Authorization errors ---


class AuthorizationError(AuthError):
    """User was authenticated but not authorized to run the agent.

    Raised by ``AuthorizationPolicy`` implementations when the
    authenticated user does not meet the required policy.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=False)
