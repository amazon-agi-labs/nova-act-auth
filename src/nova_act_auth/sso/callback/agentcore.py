"""AgentCore browser callback strategy.

Receives the OAuth authorization code by navigating a Playwright
page to the Cognito authorize URL and intercepting the redirect.
The user completes SSO in the AWS console. No localhost
server is needed.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from nova_act_auth.sso.callback.strategy import (
    CallbackStrategy,
    extract_code_from_url,
    wait_for_callback_url,
)

if TYPE_CHECKING:
    from playwright.sync_api import Page

_logger = logging.getLogger(__name__)

# Default callback URL - does not need to resolve to a real server.
# Cognito redirects the browser here; Playwright detects the URL
# change before the page actually loads.
DEFAULT_CALLBACK_URL = "https://auth.callback.internal/callback"


class AgentCoreBrowserCallback(CallbackStrategy):
    """Intercepts the OAuth redirect in a Playwright browser page.

    Instead of running a localhost HTTP server, this strategy:

    1. Navigates the provided Playwright page to the authorize URL.
    2. The user completes SSO interactively in the AWS console.
    3. Cognito redirects to the callback URL.
    4. The library reads ``code`` and ``state`` from ``page.url``.

    The callback URL does not need to point to a real server - it
    only needs to be registered in the Cognito App Client's allowed
    callback URLs.

    Args:
        page: A Playwright ``Page`` instance (from NovaAct or
            standalone Playwright).
        callback_url: The redirect URI registered in Cognito.
            Defaults to ``https://auth.callback.internal/callback``.
    """

    def __init__(
        self,
        page: Page,
        callback_url: str = DEFAULT_CALLBACK_URL,
    ) -> None:
        self._page = page
        self._callback_url = callback_url
        self._expected_state: str = ""

    def start(self, *, expected_state: str) -> None:
        self._expected_state = expected_state
        _logger.debug("AgentCore callback strategy initialized")

    @property
    def redirect_uri(self) -> str:
        return self._callback_url

    def wait_for_code(self, *, authorize_url: str, timeout: int) -> str:
        _logger.info("Navigating to Cognito authorize URL in Playwright page")
        self._page.goto(authorize_url)

        _logger.info("Waiting for SSO completion via Live View (timeout: %ds)", timeout)
        callback_url = wait_for_callback_url(self._page, self._callback_url, timeout)

        _logger.info("Callback URL received: %s", callback_url)
        return extract_code_from_url(callback_url, expected_state=self._expected_state)

    def cleanup(self) -> None:
        """
        Page lifecycle is managed by the caller (NovaAct or the developer).
        """
