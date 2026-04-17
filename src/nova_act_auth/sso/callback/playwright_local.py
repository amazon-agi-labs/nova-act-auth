"""Local Playwright callback strategy.

Launches a local Playwright Chromium browser in a fresh context
(equivalent to incognito) for SSO authentication. The redirect is
intercepted via Playwright redirect interception and URL polling -
no HTTP server is needed.

This strategy is useful for:

- Testing session save/restore without conflicting with existing
  browser sessions.
- Running SSO in an isolated environment with no pre-existing
  cookies, extensions, or saved passwords.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

from playwright.sync_api import sync_playwright

from nova_act_auth.sso.callback.agentcore import DEFAULT_CALLBACK_URL
from nova_act_auth.sso.callback.strategy import (
    CallbackStrategy,
    extract_code_from_url,
    wait_for_callback_url,
)

if TYPE_CHECKING:
    from playwright.sync_api import Browser, BrowserContext, Page, Playwright

_logger = logging.getLogger(__name__)


class PlaywrightLocalCallback(CallbackStrategy):
    """Launches a local Playwright Chromium for SSO in an isolated context.

    Unlike ``LocalhostCallback`` (which opens the system browser),
    this uses a fresh Playwright browser context with no existing
    cookies, extensions, or saved passwords - equivalent to an
    incognito window. No HTTP server is needed; the redirect is
    intercepted via Playwright's ``page.wait_for_url()``.

    Args:
        callback_url: Redirect URI registered in Cognito. Defaults
            to ``https://auth.callback.internal/callback`` (same as
            ``AgentCoreBrowserCallback``). Does not need to resolve -
            Playwright intercepts the URL change before loading.
        headless: If ``True``, run Chromium without a visible window.
            Defaults to ``False`` (visible window for interactive SSO).
    """

    def __init__(
        self,
        callback_url: str = DEFAULT_CALLBACK_URL,
        *,
        headless: bool = False,
    ) -> None:
        self._callback_url = callback_url
        self._headless = headless
        self._expected_state: str = ""
        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None

    def start(self, *, expected_state: str) -> None:
        self._expected_state = expected_state

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self._headless)
        self._context = self._browser.new_context()
        self._page = self._context.new_page()

        _logger.debug(
            "Local Playwright Chromium launched (headless=%s)",
            self._headless,
        )

    @property
    def redirect_uri(self) -> str:
        return self._callback_url

    def wait_for_code(self, *, authorize_url: str, timeout: int) -> str:
        if self._page is None:
            msg = "start() must be called before wait_for_code()"
            raise RuntimeError(msg)

        _logger.info("Navigating to Cognito authorize URL in local Chromium")
        self._page.goto(authorize_url)

        _logger.info("Waiting for SSO completion (timeout: %ds)", timeout)
        callback_url = wait_for_callback_url(self._page, self._callback_url, timeout)

        _logger.info("Callback URL received: %s", callback_url)
        return extract_code_from_url(callback_url, expected_state=self._expected_state)

    def cleanup(self) -> None:
        for resource in (self._page, self._context, self._browser):
            if resource is not None:
                with contextlib.suppress(Exception):
                    resource.close()
        if self._pw is not None:
            with contextlib.suppress(Exception):
                self._pw.stop()

        self._page = None
        self._context = None
        self._browser = None
        self._pw = None
