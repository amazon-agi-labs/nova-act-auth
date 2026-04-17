"""Token persistence backends for AuthResult.

Provides an S3 backend for saving/loading ``AuthResult`` tokens and
for persisting the profile-to-session-key mapping. All state is stored
in S3 under two prefixes:

- ``tokens/`` - serialized ``AuthResult`` objects (SSE-KMS encrypted)
- ``keys/`` - profile-to-session-key mappings (SSE-KMS encrypted)

Example::

    from nova_act_auth import S3TokenStore, build_token_store

    # Factory from env/CLI args
    store = build_token_store("s3", s3_bucket="my-bucket", s3_kms_key="alias/my-key")

    # Or construct directly
    store = S3TokenStore(bucket="my-bucket", kms_key_id="alias/my-key")

    # Load/save tokens by session key
    result = store.load("alice@co.com/corp-idp/abc123")
    store.save("alice@co.com/corp-idp/abc123", result)

    # Load/save the profile-to-session-key mapping
    store.save_session_key("default", "alice@co.com/corp-idp/abc123")
    key = store.load_session_key("default")
"""

from __future__ import annotations

import contextlib
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any

from nova_act_auth.config import AuthResult

_logger = logging.getLogger(__name__)


class TokenStoreType(StrEnum):
    """Named token store backends for ``build_token_store()``.

    Each value corresponds to a ``TokenStore`` implementation:

    - ``S3`` - S3 objects with SSE-KMS encryption
    """

    S3 = "s3"


# ---------------------------------------------------------------------------
# AuthResult serialization
# ---------------------------------------------------------------------------


def serialize(result: AuthResult) -> str:
    """Serialize an ``AuthResult`` to a JSON string."""
    data: dict[str, Any] = {
        "access_token": result.access_token,
        "id_token": result.id_token,
        "refresh_token": result.refresh_token,
        "expires_at": result.expires_at.isoformat(),
        "user_info": result.user_info,
    }
    return json.dumps(data, indent=2)


def deserialize(raw: str) -> AuthResult:
    """Deserialize a JSON string to an ``AuthResult``."""
    data = json.loads(raw)
    return AuthResult(
        access_token=data["access_token"],
        id_token=data["id_token"],
        refresh_token=data.get("refresh_token"),
        expires_at=datetime.fromisoformat(data["expires_at"]),
        user_info=data.get("user_info", {}),
    )


# ---------------------------------------------------------------------------
# Token store abstraction
# ---------------------------------------------------------------------------


class TokenStore(ABC):
    """Persists ``AuthResult`` tokens and profile-to-session-key mappings.

    Two concepts live here:

    **Session key** - the storage key for a user's tokens. Derived from
    user identity (e.g., ``email/provider/client_id``) by
    ``SessionKeyBuilder``. Stable across runs for the same user, but not
    known before the first authentication completes.

    **Profile** - a short, friendly name supplied by the caller (e.g.,
    ``"default"``, ``"work"``). Stable across machines and chosen before
    authentication. On first auth, the derived session key is saved under
    the profile name so subsequent runs can locate the tokens without
    re-authenticating.

    Lookup sequence used by ``get_or_authenticate()``:

    1. ``load_session_key(profile)`` - resolve profile to session key
    2. ``load(session_key)`` - load tokens by session key
    3. On success: ``save(session_key, result)`` + ``save_session_key(profile, session_key)``
    """

    @abstractmethod
    def load(self, key: str) -> AuthResult | None:
        """Load tokens for the given session key, or ``None`` if not found."""

    @abstractmethod
    def save(self, key: str, result: AuthResult) -> None:
        """Save tokens under the given session key."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete tokens for the given session key (no-op if not found)."""

    @abstractmethod
    def load_session_key(self, profile: str) -> str | None:
        """Return the session key saved for ``profile``, or ``None``.

        The session key is the identity-derived storage key (e.g.,
        ``alice@co.com/corp-idp/abc123``) that was recorded after the last
        successful authentication for this profile. ``None`` means no
        prior authentication has been recorded, so ``get_or_authenticate``
        will fall back to using the profile name itself as the key.
        """

    @abstractmethod
    def save_session_key(self, profile: str, key: str) -> None:
        """Persist the mapping from ``profile`` to ``key``.

        Called after every successful authentication so that the next
        call to ``load_session_key(profile)`` returns the correct
        identity-derived key without requiring re-authentication.

        **Shared-bucket warning:** profile names are stored as-is, so
        generic names like ``"default"`` will collide if multiple users
        share the same bucket. In multi-user deployments, use a profile
        name that is unique per user - the authenticated user's email
        address is a natural choice::

            profile = result.user_info["email"]   # "alice@co.com"

        Alternatively, pass the full session key as the profile name
        (e.g., ``"alice@co.com/corp-idp/client_id"``), which bypasses the
        mapping lookup entirely.
        """


class S3TokenStore(TokenStore):
    """Tokens and session key mappings in S3 with SSE-KMS encryption.

    All objects use ``ServerSideEncryption=aws:kms`` with a
    customer-managed AWS KMS key. Two S3 prefixes are used:

    - ``tokens/`` - serialized ``AuthResult`` objects
    - ``keys/`` - profile-to-session-key mappings

    Example S3 keys::

        tokens/alice@company.com/corp-idp/abc123.json
        keys/default

    Security responsibilities:

    - **KMS key policy**: restrict ``kms:Decrypt`` and ``kms:GenerateDataKey``
      to only the IAM roles that need token access. Use separate KMS keys per
      environment (dev/staging/prod) to limit blast radius. Enable CloudTrail
      data events on the key to audit all decrypt operations.
    - **S3 bucket policy**: restrict ``s3:GetObject``, ``s3:PutObject``, and
      ``s3:DeleteObject`` to only the agent process IAM role. The ``keys/``
      prefix holds profile-to-session-key mappings; an actor who can write
      to ``keys/{profile}`` can redirect where another user's tokens are
      stored. Bucket-level write access controls are the primary defence.
    """

    _PREFIX = "tokens/"
    _KEYS_PREFIX = "keys/"

    def __init__(self, bucket: str, kms_key_id: str, region: str = "us-east-1") -> None:
        import boto3

        self._bucket = bucket
        self._kms_key_id = kms_key_id
        self._s3: Any = boto3.client("s3", region_name=region)

    def _key(self, key: str) -> str:
        return f"{self._PREFIX}{key}.json"

    def load(self, key: str) -> AuthResult | None:
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=self._key(key))
            raw = response["Body"].read().decode("utf-8")
            return deserialize(raw)
        except self._s3.exceptions.NoSuchKey:
            return None
        except Exception:
            _logger.warning("Failed to load tokens from S3", exc_info=True)
            return None

    def save(self, key: str, result: AuthResult) -> None:
        self._s3.put_object(
            Bucket=self._bucket,
            Key=self._key(key),
            Body=serialize(result).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self._kms_key_id,
        )

    def delete(self, key: str) -> None:
        with contextlib.suppress(Exception):
            self._s3.delete_object(Bucket=self._bucket, Key=self._key(key))

    def load_session_key(self, profile: str) -> str | None:
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=f"{self._KEYS_PREFIX}{profile}")
            return str(response["Body"].read().decode("utf-8").strip())
        except self._s3.exceptions.NoSuchKey:
            return None
        except Exception:
            _logger.warning("Failed to load session key from S3", exc_info=True)
            return None

    def save_session_key(self, profile: str, key: str) -> None:
        self._s3.put_object(
            Bucket=self._bucket,
            Key=f"{self._KEYS_PREFIX}{profile}",
            Body=key.encode("utf-8"),
            ContentType="text/plain",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self._kms_key_id,
        )


def build_token_store(
    store: TokenStoreType | str,
    s3_bucket: str | None = None,
    s3_kms_key: str | None = None,
    region: str = "us-east-1",
) -> TokenStore:
    """Build a ``TokenStore`` from a backend name.

    Factory for built-in backends only. To use a custom backend,
    implement ``TokenStore`` and instantiate it directly — do not
    extend this function.

    Args:
        store: Backend name - a ``TokenStoreType`` enum value or
            string (``"s3"``).
        s3_bucket: S3 bucket name (required).
        s3_kms_key: AWS KMS key ID or alias for SSE-KMS encryption (required).
        region: AWS region for the S3 client.

    Returns:
        A ``TokenStore`` instance.

    Raises:
        ValueError: If ``store`` is not a valid backend name.
        ValueError: If ``s3_bucket`` or ``s3_kms_key`` is not provided.
    """
    try:
        store = TokenStoreType(store)
    except ValueError:
        valid = ", ".join(s.value for s in TokenStoreType)
        raise ValueError(f"Unknown token store '{store}'. Must be one of: {valid}") from None

    if not s3_bucket:
        raise ValueError("s3_bucket is required when store='s3'")
    if not s3_kms_key:
        raise ValueError("s3_kms_key is required when store='s3'")
    return S3TokenStore(bucket=s3_bucket, kms_key_id=s3_kms_key, region=region)
