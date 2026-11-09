"""HTTP 层鉴权门（ASGI 中间件）——家族「无 Bearer 拒/有 Bearer 放行」变体。

与 wire-ops-mcp/auth_gate.py 代码同构（家族蹈矩）：gate 不校验凭据真伪——
真校验交给上游，坏凭据 401 在工具层原样透传（上游权威）。凭据永不落日志
（缓存键 = sha256(token)）。
"""

from __future__ import annotations

import hashlib
import time

# 上游权威：本家族门「有 Bearer 即放行」，真校验（含 401）由上游/工具层负责，
# 缓存只为同一个 bearer 的去抖；因此到界整体清空即可，代价只是多判一次。
_CACHE_MAX = 1024


class AuthGate:
    def __init__(self, ttl_seconds: float = 60.0):
        self._ttl = ttl_seconds
        self._cache: dict[str, tuple[float, bool]] = {}

    def _key(self, bearer: str) -> str:
        return hashlib.sha256(bearer.encode()).hexdigest()

    async def check(self, bearer: str | None) -> bool:
        if not bearer:
            return False
        key = self._key(bearer)
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and now - hit[0] < self._ttl:
            return hit[1]
        if len(self._cache) >= _CACHE_MAX:
            self._cache.clear()  # 有界：任意 bearer 都能写一条，无界即 RSS 泄漏面
        self._cache[key] = (now, True)
        return True


class AuthGateMiddleware:
    """薄 ASGI 包装：仅拦 POST /mcp*，其余原样放行（/health 无门）。"""

    def __init__(self, app, gate: AuthGate):
        self.app = app
        self.gate = gate

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return
        path = (scope.get("path") or "").lstrip("/")
        if path != "mcp" and not path.endswith("/mcp"):
            await self.app(scope, receive, send)
            return
        bearer = _bearer_from_scope(scope)
        if await self.gate.check(bearer):
            await self.app(scope, receive, send)
            return
        # 消掉上行 body 再应答，防连接悬挂：读到完整 request 或对端断开即止
        while True:
            msg = await receive()
            if msg.get("type") == "http.disconnect":
                return
            if msg.get("type") == "http.request" and not msg.get("more_body", False):
                break
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"error": "Authentication required"}',
            }
        )


#: Headers a bearer may arrive in. `authorization` is the standard one; the MCP
#: gateway in front of us forwards the caller's token to the upstream server as
#: `x-authorization` (mcpgw `_get_registry_headers`: "X-Authorization: Bearer
#: <caller token>") and its own docstring advertises support for both. Reading
#: only the standard header therefore rejected EVERY gateway call with
#: `401 {"error": "Authentication required"}` while a direct request passed —
#: live 2026-11-09: wire-build-mcp / wire-ops-mcp dark behind the gateway, 17
#: packs declaring those tools.
_BEARER_HEADERS = (b"authorization", b"x-authorization")


def _bearer_from_scope(scope) -> str | None:
    for name, value in scope.get("headers", []):
        if name not in _BEARER_HEADERS:
            continue
        text = value.decode("latin-1")
        if text.lower().startswith("bearer "):
            token = text[7:].strip()
            if token:
                return token
    return None
