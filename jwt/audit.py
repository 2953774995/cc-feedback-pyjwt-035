"""Batch signature verification and revocation-style adjudication.

This module provides ``verify_many``, a gateway-oriented batch verifier:
thousands of tokens come in at once, each is adjudicated independently, and
a bad token never aborts the batch or raises. Parsing and signature
verification reuse :class:`jwt.api_jws.PyJWS`; this module only adds the
batching, key-resolution caching, algorithm policy, and statistics layers.

Security policy (not configurable away):

* ``algorithms=None`` defaults to the symmetric ``HS256/HS384/HS512``
  allow-list — it never widens to "accept anything".
* ``alg=none`` and any ``alg`` outside the allow-list are rejected as
  ``bad_alg`` before any key resolution or signature work happens.
* A key whose type does not match the token's ``alg`` (e.g. a PEM public
  key fed to an HMAC algorithm) is rejected as ``bad_alg`` — this is the
  classic algorithm-confusion attack surface.
"""

from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import Any, Callable, Iterable, Sequence

from .api_jwk import PyJWK
from .api_jws import PyJWS
from .exceptions import InvalidAlgorithmError, InvalidKeyError

__all__ = ["verify_many", "resolve_stats", "AuditItem", "AuditResult"]

#: Allow-list applied when the caller does not pass ``algorithms``.
#: Deliberately symmetric-only: asymmetric keys must be opted into explicitly.
_DEFAULT_ALGORITHMS = ("HS256", "HS384", "HS512")

# Reuse the PyJWS parsing and algorithm registry; the instance is stateless
# for our purposes (we never mutate its registry here).
_jws = PyJWS()

# Cumulative resolver telemetry across all verify_many() calls in this
# process. Exposed read-only via resolve_stats().
_RESOLVE_STATS = {"calls": 0, "cache_hits": 0}


def resolve_stats() -> dict[str, int]:
    """Return cumulative key-resolver statistics: ``calls`` / ``cache_hits``."""
    return dict(_RESOLVE_STATS)


class AuditItem(dict):
    """Per-token adjudication record.

    Behaves as a dict (``item["reason"]``, ``"reason" in item``) and also
    exposes attribute access (``item.reason``) for convenience.

    Fields: ``index``, ``ok``, ``reason``, ``kid``, ``alg``, ``issuer``.
    ``reason`` is one of: ``ok``, ``bad_signature``, ``expired``,
    ``not_yet_valid``, ``bad_alg``, ``missing_claim``, ``bad_audience``,
    ``malformed``, ``key_missing``.
    """

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


class AuditResult:
    """Return value of :func:`verify_many`: ``items`` + aggregate ``stats``."""

    __slots__ = ("items", "stats")

    def __init__(self, items: list[AuditItem], stats: dict[str, Any]) -> None:
        self.items = items
        self.stats = stats

    def __repr__(self) -> str:
        return f"AuditResult(ok={self.stats['ok']}, bad={self.stats['bad']})"


def _new_stats() -> dict[str, Any]:
    return {
        "ok": 0,
        "bad": 0,
        "by_reason": {},
        "by_alg": {},
        "by_issuer": {},
        "no_expiry": 0,
    }


def verify_many(
    tokens: Iterable[str | bytes],
    resolve_key: Callable[[dict[str, Any]], Any],
    algorithms: Sequence[str] | None = None,
    leeway: float | timedelta = 0,
    required_claims: Sequence[str] | None = None,
    audience: str | Sequence[str] | None = None,
) -> AuditResult:
    """Verify a batch of tokens, adjudicating each one independently.

    :param tokens: encoded JWTs (str or bytes). Any single malformed or
        invalid token is recorded with its reason and never raises.
    :param resolve_key: ``resolve_key(header) -> key or None``. Called at
        most once per distinct ``kid`` per invocation (results are cached,
        including ``None``); returning ``None`` marks the token
        ``key_missing`` and the batch continues.
    :param algorithms: allow-list for the token ``alg`` header. Defaults to
        ``HS256/HS384/HS512``. ``alg=none`` is always rejected.
    :param leeway: seconds of clock-skew tolerance for ``exp``/``nbf``/``iat``.
    :param required_claims: claims that must be present (and non-None);
        absence is reported as ``missing_claim`` and counted in
        ``stats["by_reason"]["missing_claim:<name>"]``.
    :param audience: optional expected audience; mismatch is ``bad_audience``.
    :returns: :class:`AuditResult` with per-token ``items`` and aggregate
        ``stats`` (``ok``/``bad``/``by_reason``/``by_alg``/``by_issuer``/
        ``no_expiry``).
    """
    allowed = set(algorithms) if algorithms is not None else set(_DEFAULT_ALGORITHMS)
    if isinstance(leeway, timedelta):
        leeway = leeway.total_seconds()
    required = list(required_claims or ())
    if audience is not None:
        expected_aud = {audience} if isinstance(audience, str) else set(audience)
    else:
        expected_aud = None

    items: list[AuditItem] = []
    stats = _new_stats()
    by_reason = stats["by_reason"]
    by_alg = stats["by_alg"]
    by_issuer = stats["by_issuer"]

    # Per-invocation caches: kid -> resolved key (None included), and
    # (kid, alg) -> prepared-key outcome so 10k same-key tokens pay the
    # key-preparation cost once.
    key_cache: dict[Any, Any] = {}
    prep_cache: dict[Any, tuple[Any, Any, str | None]] = {}

    now = time.time()
    exp_cutoff = now - leeway
    nbf_cutoff = now + leeway

    for index, token in enumerate(tokens):
        item = AuditItem(
            index=index, ok=False, reason="malformed", kid=None, alg=None, issuer=None
        )
        items.append(item)

        def fail(reason: str, reason_key: str | None = None) -> None:
            item["reason"] = reason
            stats["bad"] += 1
            key = reason_key if reason_key is not None else reason
            by_reason[key] = by_reason.get(key, 0) + 1

        # 1. Structural parse: 3 segments, valid base64url, JSON object header.
        try:
            payload_raw, signing_input, header, signature = _jws._load(token)
        except Exception:
            fail("malformed")
            continue

        alg = header.get("alg")
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            fail("malformed")
            continue
        item["alg"] = alg
        item["kid"] = kid
        if alg is not None:
            by_alg[alg] = by_alg.get(alg, 0) + 1

        # 2. Algorithm policy, before any key work: reject alg=none, missing
        #    alg, and anything outside the allow-list.
        if not alg or alg == "none" or alg not in allowed:
            fail("bad_alg")
            continue

        # 3. Payload must be a JSON object.
        try:
            payload = json.loads(payload_raw)
        except (ValueError, RecursionError):
            fail("malformed")
            continue
        if not isinstance(payload, dict):
            fail("malformed")
            continue

        issuer = payload.get("iss")
        item["issuer"] = issuer
        if isinstance(issuer, str):
            by_issuer[issuer] = by_issuer.get(issuer, 0) + 1

        # 4. Time claims must be numeric when present.
        exp = payload.get("exp")
        nbf = payload.get("nbf")
        iat = payload.get("iat")
        if any(
            v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)))
            for v in (exp, nbf, iat)
        ):
            fail("malformed")
            continue
        if exp is None:
            stats["no_expiry"] += 1

        # 5. Resolve the verification key, cached per kid within this call.
        if kid in key_cache:
            key = key_cache[kid]
            _RESOLVE_STATS["cache_hits"] += 1
        else:
            _RESOLVE_STATS["calls"] += 1
            try:
                key = resolve_key(header)
            except Exception:
                key = None
            key_cache[kid] = key
        if key is None:
            fail("key_missing")
            continue

        # 6. Prepare the key for the token's algorithm. A type mismatch
        #    (e.g. PEM public key as HMAC secret) is an algorithm-confusion
        #    attempt -> bad_alg, and the signature is never attempted.
        pkey = (kid, alg)
        if pkey in prep_cache:
            alg_obj, prepared, prep_err = prep_cache[pkey]
        else:
            try:
                if isinstance(key, PyJWK):
                    if key.algorithm_name != alg:
                        raise InvalidAlgorithmError(
                            f"Key algorithm {key.algorithm_name!r} does not "
                            f"match token alg {alg!r}"
                        )
                    alg_obj = key.Algorithm
                    prepared = alg_obj.prepare_key(key.key)
                else:
                    alg_obj = _jws.get_algorithm_by_name(alg)
                    prepared = alg_obj.prepare_key(key)
                prep_err = None
            except (InvalidKeyError, InvalidAlgorithmError, NotImplementedError):
                alg_obj = prepared = None
                prep_err = "bad_alg"
            prep_cache[pkey] = (alg_obj, prepared, prep_err)
        if prep_err is not None:
            fail(prep_err)
            continue

        # 7. Signature verification via the PyJWS algorithm object.
        try:
            sig_ok = alg_obj.verify(signing_input, prepared, signature)
        except Exception:
            sig_ok = False
        if not sig_ok:
            fail("bad_signature")
            continue

        # 8. Time-based claims, relaxed by leeway seconds.
        if exp is not None and exp <= exp_cutoff:
            fail("expired")
            continue
        if nbf is not None and nbf > nbf_cutoff:
            fail("not_yet_valid")
            continue
        if iat is not None and iat > nbf_cutoff:
            fail("not_yet_valid")
            continue

        # 9. Required claims.
        missing = next((c for c in required if payload.get(c) is None), None)
        if missing is not None:
            fail("missing_claim", f"missing_claim:{missing}")
            continue

        # 10. Audience (only when the caller asks for it).
        if expected_aud is not None:
            aud_claim = payload.get("aud")
            if isinstance(aud_claim, str):
                token_aud = {aud_claim}
            elif isinstance(aud_claim, list):
                token_aud = set(aud_claim)
            else:
                token_aud = set()
            if not token_aud & expected_aud:
                fail("bad_audience")
                continue

        item["ok"] = True
        item["reason"] = "ok"
        stats["ok"] += 1

    return AuditResult(items, stats)
