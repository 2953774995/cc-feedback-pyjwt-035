#!/usr/bin/env python3
"""验收探针：批量验签与算法策略（10 条契约）。

设计原则：
  · 每条探针独立，一条失败不影响其余探针；
  · 在未实现 `jwt.audit` 的基线上，10 条全部 FAIL；
  · 只依赖标准库与仓库自带的 jwt，不引入新的第三方包。
"""
import base64
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

KEY = b"probe-secret-key-0123456789abcdef"
OTHER = b"another-key-9876543210"


# ---------- JWT 构造（不依赖被测实现，避免探针自身被实现污染） ----------
def _b64(raw):
    if isinstance(raw, str):
        raw = raw.encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make(payload, key=KEY, alg="HS256", kid=None, header_extra=None):
    head = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        head["kid"] = kid
    if header_extra:
        head.update(header_extra)
    h = _b64(json.dumps(head, separators=(",", ":")))
    p = _b64(json.dumps(payload, separators=(",", ":")))
    signing = f"{h}.{p}"
    if alg == "none":
        return f"{signing}."
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    sig = hmac.new(key, signing.encode(), digest).digest()
    return f"{signing}.{_b64(sig)}"


def _payload(**kw):
    now = int(time.time())
    base = {"iss": "issuer-a", "sub": "u1", "exp": now + 600, "iat": now - 30}
    base.update(kw)
    return base


# ---------- 探针框架 ----------
RESULTS = []


def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:  # 未实现、导入失败等一律记 FAIL，不中断
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn

    return deco


def audit():
    import jwt.audit as m  # noqa: F401  未实现时抛 ModuleNotFoundError

    return m


@probe("P01 批量入口与成功项结构")
def p01():
    m = audit()
    tokens = [_make(_payload(sub=f"u{i}"), kid="k1") for i in range(3)]
    out = m.verify_many(tokens, lambda header: KEY)
    assert hasattr(out, "items") and hasattr(out, "stats"), "verify_many 需返回 items 与 stats"
    assert len(out.items) == 3, f"应返回 3 条，实际 {len(out.items)}"
    first = out.items[0]
    for key in ("index", "ok", "reason", "kid", "alg", "issuer"):
        assert key in first, f"item 缺字段 {key}"
    assert all(i.ok for i in out.items) and out.stats["ok"] == 3, "三条合法 token 应全部通过"


@probe("P02 alg=none 与白名单外算法一律拒签")
def p02():
    m = audit()
    none_tok = _make(_payload(), alg="none", kid="k1")
    hs512_tok = _make(_payload(), alg="HS512", kid="k1")
    out = m.verify_many([none_tok, hs512_tok], lambda header: KEY, algorithms=["HS256"])
    assert out.items[0].reason == "bad_alg", f"alg=none 应为 bad_alg，实际 {out.items[0].reason}"
    assert out.items[1].reason == "bad_alg", f"HS512 不在白名单应为 bad_alg，实际 {out.items[1].reason}"


@probe("P03 签名错误与密钥类型不匹配")
def p03():
    m = audit()
    bad_sig = _make(_payload(), key=OTHER, kid="k1")
    out = m.verify_many([bad_sig], lambda header: KEY)
    assert out.items[0].reason == "bad_signature", f"应为 bad_signature，实际 {out.items[0].reason}"
    pem_like = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"
    out2 = m.verify_many([_make(_payload(), kid="k1")], lambda header: pem_like)
    assert out2.items[0].reason == "bad_alg", f"公钥当 HMAC 密钥应判 bad_alg，实际 {out2.items[0].reason}"


@probe("P04 kid 解析缓存只调一次")
def p04():
    m = audit()
    tokens = [_make(_payload(sub=f"u{i}"), kid="same-kid") for i in range(5)]
    calls = {"n": 0}

    def resolver(header):
        calls["n"] += 1
        return KEY

    out = m.verify_many(tokens, resolver)
    assert all(i.ok for i in out.items), "五条同 kid 的合法 token 应全部通过"
    assert calls["n"] == 1, f"同 kid 应只解析一次，实际调用 {calls['n']} 次"
    stats = m.resolve_stats()
    assert stats["calls"] >= 1 and stats["cache_hits"] >= 4, f"缓存统计不对：{stats}"


@probe("P05 job 缺失密钥键与 key_missing")
def p05():
    m = audit()
    mixed = [_make(_payload(), kid="k1"), _make(_payload(), kid="unknown-kid")]
    out = m.verify_many(mixed, lambda header: KEY if header.get("kid") == "k1" else None)
    assert out.items[0].ok, "已知 kid 应通过"
    assert out.items[1].reason == "key_missing", f"未知 kid 应为 key_missing，实际 {out.items[1].reason}"
    assert out.stats["bad"] == 1, f"bad 计数应为 1，实际 {out.stats['bad']}"


@probe("P06 过期、未生效与 leeway")
def p06():
    m = audit()
    now = int(time.time())
    expired = _make(_payload(exp=now - 10, iat=now - 100), kid="k1")
    future = _make(_payload(nbf=now + 60, exp=now + 600), kid="k1")
    out = m.verify_many([expired], lambda header: KEY)
    assert out.items[0].reason == "expired", f"应为 expired，实际 {out.items[0].reason}"
    out2 = m.verify_many([expired], lambda header: KEY, leeway=30)
    assert out2.items[0].ok, "leeway=30 时过期 10 秒应放行"
    out3 = m.verify_many([future], lambda header: KEY)
    assert out3.items[0].reason == "not_yet_valid", f"应为 not_yet_valid，实际 {out3.items[0].reason}"


@probe("P07 缺 exp 与必填 claim")
def p07():
    m = audit()
    no_exp = _make({"iss": "issuer-a", "sub": "u1", "iat": int(time.time())}, kid="k1")
    out = m.verify_many([no_exp], lambda header: KEY)
    assert out.items[0].ok, "缺 exp 不应判过期"
    assert out.stats["no_expiry"] == 1, f"no_expiry 应为 1，实际 {out.stats.get('no_expiry')}"
    missing = _make({"iss": "issuer-a", "exp": int(time.time()) + 60}, kid="k1")
    out2 = m.verify_many([missing], lambda header: KEY, required_claims=["sub"])
    assert out2.items[0].reason == "missing_claim", f"应为 missing_claim，实际 {out2.items[0].reason}"
    assert any("sub" in k for k in out2.stats["by_reason"]), f"by_reason 未细分到 claim 名：{out2.stats['by_reason']}"


@probe("P08 坏 token 不中断整批")
def p08():
    m = audit()
    good = _make(_payload(), kid="k1")
    mixed = ["not-a-jwt", "a.b.c", _b64('{"alg":"HS256"}') + ".bm90anNvbg.xx", good]
    out = m.verify_many(mixed, lambda header: KEY)
    assert len(out.items) == 4, f"应返回 4 条，实际 {len(out.items)}"
    assert [i.reason for i in out.items[:3]] == ["malformed"] * 3, f"前三条应为 malformed，实际 {[i.reason for i in out.items[:3]]}"
    assert out.items[3].ok, "最后一条合法 token 应通过"


@probe("P09 统计口径与空输入")
def p09():
    m = audit()
    toks = [
        _make(_payload(sub="a", iss="issuer-a"), kid="k1"),
        _make(_payload(sub="b", iss="issuer-b"), kid="k2"),
        _make(_payload(sub="c", iss="issuer-b", exp=int(time.time()) - 5), kid="k2"),
    ]
    out = m.verify_many(toks, lambda header: KEY)
    st = out.stats
    assert st["ok"] == 2 and st["bad"] == 1, f"ok/bad 计数不对：{st}"
    assert st["by_issuer"].get("issuer-b") == 2, f"by_issuer 不对：{st['by_issuer']}"
    assert st["by_alg"].get("HS256") == 3, f"by_alg 不对：{st['by_alg']}"
    empty = m.verify_many([], lambda header: KEY)
    assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空 items 与零计数"


@probe("P10 万级性能与既有 API 不回归")
def p10():
    m = audit()
    tokens = [_make(_payload(sub=f"u{i}"), kid="k1") for i in range(10000)]
    t0 = time.perf_counter()
    out = m.verify_many(tokens, lambda header: KEY)
    cost = time.perf_counter() - t0
    assert out.stats["ok"] == 10000, f"万条应全部通过，实际 {out.stats['ok']}"
    assert cost < 3.0, f"万条验签耗时 {cost:.2f}s 超过 3s"
    import jwt

    assert jwt.decode(jwt.encode({"a": 1}, "k", algorithm="HS256"), "k", algorithms=["HS256"]) == {"a": 1}


def main():
    print("=" * 60)
    print("验收探针：批量验签与算法策略（10 条契约）")
    print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        if ok:
            print(f"PASS  {name}")
        else:
            print(f"FAIL  {name}")
            print(f"      {detail}")
    print("-" * 60)
    print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
