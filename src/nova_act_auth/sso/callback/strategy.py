"""Callback strategy abstraction for receiving the OAuth authorization code.

Defines the ``CallbackStrategy`` ABC and generic URL parsing utilities
used by all concrete callback implementations.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from authlib.oauth2.rfc6749.errors import MismatchingStateException, MissingCodeException
from authlib.oauth2.rfc6749.parameters import parse_authorization_code_response

from nova_act_auth.errors import SSOError, SSOInvalidStateError, SSOTimeoutError

if TYPE_CHECKING:
    from playwright.sync_api import Page

_PAGE_STYLE = """\
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                 'Helvetica Neue', Arial, sans-serif;
    background: linear-gradient(135deg, #f0f4f8 0%, #d9e2ec 100%);
    color: #334e68;
  }
  .card {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08);
    padding: 48px 56px;
    text-align: center;
    max-width: 420px;
  }
  .icon {
    width: 56px; height: 56px;
    border-radius: 50%;
    display: flex; justify-content: center; align-items: center;
    margin: 0 auto 24px;
  }
  .icon svg { width: 28px; height: 28px; }
  h1 {
    font-size: 1.35rem; font-weight: 600;
    margin-bottom: 8px; color: #243b53;
  }
  p {
    font-size: 0.95rem; line-height: 1.5;
    color: #627d98;
  }
</style>"""

SSO_SUCCESS_HTML = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authentication complete</title>
{_PAGE_STYLE}
</head>
<body>
<div class="card">
  <div class="icon" style="background: #e6f6ed;">
    <svg viewBox="0 0 24 24" fill="none" stroke="#27ab6e" stroke-width="2.5"
         stroke-linecap="round" stroke-linejoin="round">
      <path d="M20 6L9 17l-5-5"/>
    </svg>
  </div>
  <h1>Identity verified</h1>
  <p>You have been authenticated. The agent is now authorized to run.</p>
  <p>You can close this window and return to the terminal.</p>
</div>
</body>
</html>"""


def sso_error_html(message: str) -> str:
    """Build an error page with the same styling as the success page."""
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authentication failed</title>
{_PAGE_STYLE}
</head>
<body>
<div class="card">
  <div class="icon" style="background: #fce4e4;">
    <svg viewBox="0 0 24 24" fill="none" stroke="#e12d39" stroke-width="2.5"
         stroke-linecap="round" stroke-linejoin="round">
      <path d="M18 6L6 18"/><path d="M6 6l12 12"/>
    </svg>
  </div>
  <h1>Authentication failed</h1>
  <p>{message}</p>
  <p>Please return to the terminal.</p>
</div>
</body>
</html>"""


_logger = logging.getLogger(__name__)


class CallbackStrategy(ABC):
    """Abstract base class for OAuth callback strategies.

    Each strategy handles two concerns:
    1. How to present the authorize URL to the user (system browser, Playwright page, etc.)
    2. How to receive the authorization code back (localhost HTTP server, URL interception, etc.)

    Usage in ``authenticate()``::

        callback.start(expected_state=state)
        try:
            redirect_uri = callback.redirect_uri
            authorize_url = build_url(..., redirect_uri=redirect_uri)
            code = callback.wait_for_code(authorize_url=authorize_url, timeout=120)
        finally:
            callback.cleanup()
    """

    @abstractmethod
    def start(self, *, expected_state: str) -> None:
        """Initialize resources needed before building the authorize URL.

        For ``LocalhostCallback`` this starts the HTTP server (which
        determines the actual port). For other strategies this may be
        a no-op.

        After ``start()`` returns, ``redirect_uri`` will return
        the correct value.
        """

    @property
    @abstractmethod
    def redirect_uri(self) -> str:
        """The ``redirect_uri`` to include in the Cognito authorize URL.

        Only valid after ``start()`` has been called.
        """

    @abstractmethod
    def wait_for_code(self, *, authorize_url: str, timeout: int) -> str:
        """Present the authorize URL to the user and wait for the callback.

        This method handles both opening/navigating to the URL and
        waiting for the authorization code to arrive.

        Args:
            authorize_url: Full Cognito ``/oauth2/authorize`` URL.
            timeout: Maximum seconds to wait for the user to complete SSO.

        Returns:
            The authorization code from the callback.

        Raises:
            SSOTimeoutError: User did not complete SSO in time.
            SSOInvalidStateError: State parameter mismatch (CSRF).
            SSOError: Cognito returned an error or code was missing.
        """

    @abstractmethod
    def cleanup(self) -> None:
        """Release resources (stop server, close connections, etc.).

        Must be safe to call multiple times.
        """


# ---------------------------------------------------------------------------
# URL interception utilities (used by AgentCore and Playwright strategies)
# ---------------------------------------------------------------------------


def wait_for_callback_url(page: Page, callback_url: str, timeout: int) -> str:
    """Wait for the browser to navigate to the callback URL.

    The callback URL (e.g. ``https://auth.callback.internal/callback``)
    does not point to a real server. Cognito redirects the browser
    there after SSO completes. This function detects the redirect via
    two mechanisms:

    1. ``page.url`` check - if the browser navigated successfully
       (e.g. via a route intercept in AgentCore).
    2. Redirect interception - when DNS resolution fails for the
       non-resolvable callback host, Playwright captures the full
       URL including the authorization code in the query string.

    Args:
        page: The Playwright page to monitor.
        callback_url: The registered redirect URI prefix.
        timeout: Maximum seconds to wait.

    Returns:
        The full callback URL with query parameters.

    Raises:
        SSOTimeoutError: If the callback URL is not detected
            within the timeout.
    """
    captured_url: list[str | None] = [None]

    def _on_request_failed(request) -> None:  # type: ignore[no-untyped-def]
        if request.url.startswith(callback_url):
            _logger.info("SSO callback received via redirect interception: %s", request.url)
            captured_url[0] = request.url

    page.on("requestfailed", _on_request_failed)

    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # Check if the page navigated to the callback URL
            # (happens when a route intercept fulfills the request)
            current_url = page.url
            if isinstance(current_url, str) and current_url.startswith(callback_url):
                _logger.info("Callback URL detected via page navigation: %s", current_url)
                _show_complete_page(page)
                return current_url

            # Check if redirect interception captured the URL
            # (happens when DNS fails for the non-resolvable callback host)
            if captured_url[0] is not None:
                _show_complete_page(page)
                return captured_url[0]

            # Process Playwright events and wait
            page.wait_for_timeout(500)

        raise SSOTimeoutError(f"SSO login timed out after {timeout}s. User did not complete authentication.")
    finally:
        page.remove_listener("requestfailed", _on_request_failed)


def _show_complete_page(page: Page) -> None:
    """Show a friendly 'Authentication complete' page.

    Replaces the 'This site can't be reached' error that appears
    when the non-resolvable callback URL fails DNS resolution.
    Pauses briefly so the user can see the confirmation before
    the browser is closed by cleanup().
    """
    try:
        page.set_content(SSO_SUCCESS_HTML, wait_until="commit")
        page.wait_for_timeout(3000)
    except Exception:
        _logger.debug("Could not show completion page", exc_info=True)


def extract_code_from_url(url: str, *, expected_state: str) -> str:
    """Parse the authorization code from a Cognito redirect URL.

    Uses authlib's ``parse_authorization_code_response`` (RFC 6749
    Section 4.1.2) for code/state extraction and validation.

    Args:
        url: The full callback URL with query parameters.
        expected_state: The OAuth state value to validate against.

    Returns:
        The authorization code.

    Raises:
        SSOError: If the URL contains an error or is missing the code.
        SSOInvalidStateError: If the state parameter does not match.
    """
    # Check for error response first (RFC 6749 Section 4.1.2.1).
    # authlib's parse_authorization_code_response does not handle this.
    query_params = parse_qs(urlparse(url).query)
    error = query_params.get("error", [""])[0]
    if error:
        desc = query_params.get("error_description", ["Unknown error"])[0]
        raise SSOError(f"Cognito returned error: {error} - {desc}")

    try:
        params = parse_authorization_code_response(url, state=expected_state)
    except MissingCodeException as exc:
        raise SSOError("Callback URL is missing the authorization code.") from exc
    except MismatchingStateException as exc:
        raise SSOInvalidStateError(
            "OAuth state parameter mismatch. The callback state does not "
            "match the expected value. This may indicate a CSRF attack or "
            "a stale callback from a previous authentication attempt."
        ) from exc

    return str(params["code"])
