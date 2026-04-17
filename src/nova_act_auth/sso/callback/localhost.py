"""Localhost OAuth callback strategy.

Opens the system browser to the Cognito authorize URL and runs
an HTTP server on localhost to receive the authorization code
from the redirect. Uses threading so the main thread can wait
with a timeout.
"""

from __future__ import annotations

import logging
import threading
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from nova_act_auth.errors import (
    SSOBrowserError,
    SSOError,
    SSOInvalidStateError,
    SSOTimeoutError,
)
from nova_act_auth.sso.callback.strategy import (
    SSO_SUCCESS_HTML,
    CallbackStrategy,
    sso_error_html,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Browser launcher
# ---------------------------------------------------------------------------


def open_browser(url: str) -> None:
    """Open the system browser to the given URL.

    Uses Python's ``webbrowser`` module which supports macOS,
    Windows, and Linux (xdg-open).

    Raises:
        SSOBrowserError: If the browser could not be opened.
    """
    _logger.debug("Opening system browser for SSO login")
    try:
        success = webbrowser.open(url)
        if not success:
            raise SSOBrowserError(
                "Could not open system browser. "
                "If running in a headless environment, "
                "SSO requires an interactive session with a browser."
            )
    except SSOBrowserError:
        raise
    except Exception as exc:
        raise SSOBrowserError(
            f"Failed to open system browser: {exc}. "
            "If running in a headless environment, "
            "SSO requires an interactive session with a browser."
        ) from exc


# ---------------------------------------------------------------------------
# HTTP callback server
# ---------------------------------------------------------------------------


@dataclass
class _CallbackResult:
    """Mutable container for the OAuth callback parameters."""

    code: str = ""
    state: str = ""
    error: str = ""
    error_description: str = ""


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth authorization code."""

    # Set by the factory before requests are served.
    _result: _CallbackResult
    _received: threading.Event

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Handle error responses from Cognito / IdP
        error = params.get("error", [""])[0]
        if error:
            self._result.error = error
            self._result.error_description = params.get("error_description", ["Unknown error"])[0]
            self._send(
                HTTPStatus.BAD_REQUEST,
                sso_error_html(self._result.error_description),
            )
            self._received.set()
            return

        code = params.get("code", [""])[0]
        state = params.get("state", [""])[0]

        if not code:
            self._send(
                HTTPStatus.BAD_REQUEST,
                sso_error_html("Missing authorization code."),
            )
            return

        self._result.code = code
        self._result.state = state
        self._send(HTTPStatus.OK, SSO_SUCCESS_HTML)
        self._received.set()

    def _send(self, status: HTTPStatus, html: str) -> None:
        self.send_response(status.value)
        # https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Callback URL contains the authorization code - don't cache.
        # https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control
        self.send_header("Cache-Control", "no-store")
        # Disable MIME sniffing.
        # https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        """Route HTTP request logs through the standard logger
        instead of printing to stderr."""
        _logger.debug(format, *args)


@dataclass
class _CallbackServerContext:
    """Handle to a running callback server."""

    port: int
    """Actual port the server is listening on."""

    _server: HTTPServer = field(repr=False)
    _thread: threading.Thread = field(repr=False)
    _result: _CallbackResult = field(repr=False)
    _received: threading.Event = field(repr=False)
    _expected_state: str = field(repr=False)

    def shutdown(self) -> None:
        """Stop the server and join the background thread."""
        self._server.shutdown()
        self._thread.join(timeout=5)


def _start_callback_server(
    *,
    port: int,
    expected_state: str,
) -> _CallbackServerContext:
    """Start the localhost callback server in a daemon thread.

    Returns immediately with a context that holds the actual port
    and can be passed to ``_wait_for_callback()``.
    """
    result = _CallbackResult()
    received = threading.Event()

    # Create a handler subclass with the shared state injected.
    handler_class = type(
        "_BoundCallbackHandler",
        (_CallbackHandler,),
        {"_result": result, "_received": received},
    )

    try:
        server = HTTPServer(("127.0.0.1", port), handler_class)
    except OSError as exc:
        raise SSOError(
            f"Port {port} is already in use. Free the port or set a different "
            f"callback_port in AuthConfig. The same port must be registered as "
            f"a callback URL in your Cognito App Client."
        ) from exc

    actual_port: int = server.server_address[1]

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
        name="sso-callback-server",
    )
    thread.start()
    _logger.debug("Callback server listening on 127.0.0.1:%d", actual_port)

    return _CallbackServerContext(
        port=actual_port,
        _server=server,
        _thread=thread,
        _result=result,
        _received=received,
        _expected_state=expected_state,
    )


def _wait_for_callback(
    *,
    server_ctx: _CallbackServerContext,
    timeout: int,
) -> str:
    """Block until the OAuth callback arrives or *timeout* elapses.

    Returns:
        The authorization code from the callback.

    Raises:
        SSOTimeoutError: User did not complete SSO within *timeout*.
        SSOInvalidStateError: State parameter does not match.
        SSOError: Cognito returned an error response.
    """
    if not server_ctx._received.wait(timeout=timeout):
        raise SSOTimeoutError(
            f"SSO login timed out after {timeout} seconds. The user did not complete authentication in time."
        )

    result = server_ctx._result

    if result.error:
        raise SSOError(f"Cognito returned error: {result.error} - {result.error_description}")

    if result.state != server_ctx._expected_state:
        raise SSOInvalidStateError(
            "OAuth state parameter mismatch. The callback state does not "
            "match the expected value. This may indicate a CSRF attack or "
            "a stale callback from a previous authentication attempt."
        )

    return result.code


# ---------------------------------------------------------------------------
# LocalhostCallback strategy
# ---------------------------------------------------------------------------


class LocalhostCallback(CallbackStrategy):
    """Receives the OAuth callback via a localhost HTTP server.

    Opens the system browser to the authorize URL and listens
    for Cognito's redirect on a local port.

    Args:
        port: Preferred localhost port. Falls back to a random
            port if unavailable.
    """

    def __init__(self, port: int = 8976) -> None:
        self._port = port
        self._server_ctx: _CallbackServerContext | None = None
        self._expected_state: str = ""

    def start(self, *, expected_state: str) -> None:
        self._expected_state = expected_state
        self._server_ctx = _start_callback_server(
            port=self._port,
            expected_state=expected_state,
        )
        _logger.debug("Localhost callback server started on port %d", self._server_ctx.port)

    @property
    def redirect_uri(self) -> str:
        if self._server_ctx is not None:
            return f"http://localhost:{self._server_ctx.port}/callback"
        return f"http://localhost:{self._port}/callback"

    def wait_for_code(self, *, authorize_url: str, timeout: int) -> str:
        if self._server_ctx is None:
            msg = "start() must be called before wait_for_code()"
            raise RuntimeError(msg)

        open_browser(authorize_url)
        return _wait_for_callback(server_ctx=self._server_ctx, timeout=timeout)

    def cleanup(self) -> None:
        if self._server_ctx is not None:
            self._server_ctx.shutdown()
            self._server_ctx = None
