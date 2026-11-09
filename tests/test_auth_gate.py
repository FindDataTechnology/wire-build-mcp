"""AuthGate（家族变体）：无 Bearer 拒、有 Bearer 放行。"""

from __future__ import annotations

from wire_build_mcp.auth_gate import _CACHE_MAX, AuthGate


async def test_anonymous_rejected():
    assert await AuthGate().check(None) is False


async def test_any_bearer_passes():
    assert await AuthGate().check("anything") is True


async def test_cache_is_bounded():
    # 每个不同 bearer 都会写一条缓存键：没有上界就是长跑进程的 RSS 泄漏面
    gate = AuthGate()
    for i in range(_CACHE_MAX * 4):
        await gate.check(f"tok-{i}")
    assert len(gate._cache) <= _CACHE_MAX


def test_gateway_header_is_accepted():
    """The gateway forwards the caller's token as `x-authorization`; reading only
    the standard header made every proxied call a 401 (live 2026-11-09)."""
    from wire_build_mcp.auth_gate import _bearer_from_scope

    scope = {"headers": [(b"x-authorization", b"Bearer caller-token")]}
    assert _bearer_from_scope(scope) == "caller-token"


def test_standard_header_still_wins_and_empty_values_are_ignored():
    from wire_build_mcp.auth_gate import _bearer_from_scope

    assert _bearer_from_scope({"headers": [(b"authorization", b"Bearer direct")]}) == "direct"
    assert _bearer_from_scope({"headers": [(b"x-authorization", b"Bearer  ")]}) is None
    assert _bearer_from_scope({"headers": [(b"x-authorization", b"Basic abc")]}) is None
    assert _bearer_from_scope({"headers": []}) is None
