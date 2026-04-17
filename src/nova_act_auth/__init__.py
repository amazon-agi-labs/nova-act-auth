"""Amazon Nova Act Auth - inbound authentication for AI agents.

Verifies who the user is before the agent is allowed to run.
Currently provides Cognito PKCE OAuth2 SSO as the authentication
mechanism - handling the login flow (authenticate, token exchange,
token refresh) and returning ``AuthResult`` with JWT tokens and user
identity. Includes pluggable token persistence via ``TokenStore``
backends (S3). Browser session persistence is handled
separately by the NovaAct SDK's ``BrowserSessionProvider``.

Usage::

    from nova_act_auth import (
        AuthConfig, AllowedDomainsPolicy, get_or_authenticate,
    )

    config = AuthConfig.from_env()
    result = get_or_authenticate(config)

    policy = AllowedDomainsPolicy(["company.com"])
    policy.authorize(result)  # raises AuthorizationError if denied

    print(result.user_info["email"])

``get_or_authenticate`` handles the full authentication lifecycle -
cached token lookup, silent refresh, interactive SSO fallback, and
persistence. ``AuthorizationPolicy`` provides an extensible layer
for authorization checks after authentication. For lower-level
control, use ``authenticate()`` directly with a ``CallbackStrategy``
instance.
"""

__version__ = "1.0.0"

from nova_act_auth.authorization import (
    AllowAllPolicy,
    AllowedDomainsPolicy,
    AuthorizationPolicy,
)
from nova_act_auth.config import (
    AuthConfig,
    AuthResult,
    CallbackStrategyType,
    SessionKeyBuilder,
)
from nova_act_auth.errors import (
    AuthError,
    AuthorizationError,
    SSOBrowserError,
    SSOError,
    SSOInvalidStateError,
    SSOTimeoutError,
    SSOTokenExchangeError,
)
from nova_act_auth.sso.authenticate import (
    authenticate,
    get_or_authenticate,
    refresh_tokens,
)
from nova_act_auth.sso.callback.agentcore import AgentCoreBrowserCallback
from nova_act_auth.sso.callback.localhost import LocalhostCallback
from nova_act_auth.sso.callback.playwright_local import PlaywrightLocalCallback
from nova_act_auth.sso.callback.strategy import CallbackStrategy
from nova_act_auth.token_store import (
    S3TokenStore,
    TokenStore,
    TokenStoreType,
    build_token_store,
    deserialize,
    serialize,
)

__all__ = [
    "AgentCoreBrowserCallback",
    "AllowAllPolicy",
    "AllowedDomainsPolicy",
    "AuthConfig",
    "AuthError",
    "AuthResult",
    "AuthorizationError",
    "AuthorizationPolicy",
    "CallbackStrategy",
    "CallbackStrategyType",
    "LocalhostCallback",
    "PlaywrightLocalCallback",
    "S3TokenStore",
    "SSOBrowserError",
    "SSOError",
    "SSOInvalidStateError",
    "SSOTimeoutError",
    "SSOTokenExchangeError",
    "SessionKeyBuilder",
    "TokenStore",
    "TokenStoreType",
    "authenticate",
    "build_token_store",
    "deserialize",
    "get_or_authenticate",
    "refresh_tokens",
    "serialize",
]
