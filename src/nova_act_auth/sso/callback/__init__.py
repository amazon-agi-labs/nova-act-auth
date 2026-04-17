"""Callback strategies for receiving the OAuth authorization code."""

from nova_act_auth.sso.callback.agentcore import AgentCoreBrowserCallback
from nova_act_auth.sso.callback.localhost import LocalhostCallback
from nova_act_auth.sso.callback.playwright_local import PlaywrightLocalCallback
from nova_act_auth.sso.callback.strategy import CallbackStrategy

__all__ = [
    "AgentCoreBrowserCallback",
    "CallbackStrategy",
    "LocalhostCallback",
    "PlaywrightLocalCallback",
]
