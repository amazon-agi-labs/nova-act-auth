"""Authorization policies for gating agent execution.

After authentication proves the user's identity, an authorization
policy decides whether that user is allowed to run the agent.
The library ships built-in policies for common patterns and an
``AuthorizationPolicy`` ABC for custom logic. See
``AUTHORIZATION.md`` for a guide covering all approaches.

Usage::

    from nova_act_auth import get_or_authenticate, AllowedDomainsPolicy

    policy = AllowedDomainsPolicy(["company.com", "partner.org"])
    result = get_or_authenticate(config)
    policy.authorize(result)
    # If we get here, the user is authorized to run the agent.

Built-in policies:

- ``AllowAllPolicy`` - permits all authenticated users (default).
- ``AllowedDomainsPolicy`` - checks email domain against an allowlist.

For more advanced authorization (Amazon Cognito groups, Amazon Verified
Permissions, etc.), extend ``AuthorizationPolicy`` with your own
implementation. See ``AUTHORIZATION.md`` for examples and
``samples/sso_then_agent.py`` for runnable code.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from nova_act_auth.errors import AuthorizationError

if TYPE_CHECKING:
    from nova_act_auth.config import AuthResult

_logger = logging.getLogger(__name__)


class AuthorizationPolicy(ABC):
    """Decides whether an authenticated user may run the agent.

    Subclass this to implement authorization logic. The ``authorize``
    method receives the ``AuthResult`` from authentication and should
    raise ``AuthorizationError`` if the user is not permitted.

    The library does not enforce authorization automatically -
    call ``policy.authorize(result)`` after authentication in your
    agent code.

    Security note: the security of an authorization policy is only as
    strong as the controls around its configuration. Domain allowlists,
    group names, and policy store IDs should be treated as security-sensitive
    configuration: store them in version-controlled config with restricted
    write access, and apply the same review process as code changes. An
    attacker who can modify policy configuration can bypass or break
    authorization without touching application code.
    """

    @abstractmethod
    def authorize(self, result: AuthResult) -> None:
        """Check whether the user is authorized.

        Args:
            result: The authentication result containing user
                identity claims.

        Raises:
            AuthorizationError: If the user is not authorized.
        """


class AllowAllPolicy(AuthorizationPolicy):
    """Allows all authenticated users. No restrictions.

    This is the default behavior when no policy is configured.
    Any user who passes authentication is authorized.
    """

    def authorize(self, result: AuthResult) -> None:
        _logger.debug("AllowAllPolicy: user authorized (no restrictions)")


class AllowedDomainsPolicy(AuthorizationPolicy):
    """Authorizes users whose email domain is in an allowlist.

    Example::

        policy = AllowedDomainsPolicy(["company.com", "partner.org"])
        policy.authorize(result)  # raises if email is not @company.com or @partner.org

    Args:
        domains: List of allowed email domains (case-insensitive).
    """

    def __init__(self, domains: list[str]) -> None:
        self._domains: set[str] = {d.lower().strip() for d in domains}

    def authorize(self, result: AuthResult) -> None:
        email = result.user_info.get("email", "")
        if not email or "@" not in email:
            raise AuthorizationError("Cannot authorize: authentication result has no email claim.")
        domain = email.rsplit("@", 1)[1].lower()
        if domain not in self._domains:
            allowed = ", ".join(sorted(self._domains))
            raise AuthorizationError(
                f"User '{email}' is not authorized. Email domain '{domain}' is not in the allowed list: {allowed}."
            )
        _logger.info("AllowedDomainsPolicy: user '%s' authorized", email)
