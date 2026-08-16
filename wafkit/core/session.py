"""Transporte HTTP 100% stdlib (urllib/http.client).

- requests nao e necessario: urllib cobre GET/POST, headers, cookies, proxy.
- Transfer-Encoding: chunked via http.client (urllib nao suporta).
- TLS com contexto nao-verificado (alvo de pentest, aceita certs invalidos).
"""

from __future__ import annotations

import http.client
import random
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request

from wafkit.evasions.base import ProbeContext


class _Resp:
    """Mini-resposta com a interface usada pelo resto do projeto."""

    def __init__(self, status: int, body: bytes, headers: dict):
        self.status_code = status
        self.status = status
        self.content = body
        self.text = body.decode("utf-8", "ignore")
        self.headers = headers


class SessionFactory:
    """Fabrica de sessoes HTTP: proxy rotativo + envio chunked (stdlib)."""

    def __init__(self, settings):
        self.settings = settings
        self._idx = 0
        self._lock = threading.Lock()
        if settings.tls.http2 or settings.tls.impersonate:
            print("[!] aviso: HTTP/2 e impersonate TLS exigem curl_cffi; "
                  "ignorados (modo stdlib)")

    # ---- proxy ----
    def _proxy(self):
        proxies = self.settings.proxies
        if not proxies:
            return None
        with self._lock:
            if self.settings.proxy_rotation == "round_robin":
                p = proxies[self._idx % len(proxies)]
                self._idx += 1
            else:
                p = random.choice(proxies)
        return p

    def _opener(self):
        p = self._proxy()
        if p:
            return urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": p, "https": p}))
        return urllib.request.build_opener()

    # ---- usado pelo baseline ----
    def request(self, method, url, params=None, data=None, headers=None,
                timeout=10):
        headers = dict(headers or {})
        full_url = url
        if params:
            sep = "&" if "?" in full_url else "?"
            full_url = full_url + sep + urllib.parse.urlencode(params)
        body = None
        if data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode()
                headers.setdefault("Content-Type",
                                   "application/x-www-form-urlencoded")
            else:
                body = data.encode() if isinstance(data, str) else data
        req = urllib.request.Request(full_url, data=body, headers=headers,
                                     method=method)
        try:
            resp = self._opener().open(req, timeout=timeout)
            return _Resp(resp.status, resp.read(), dict(resp.headers))
        except urllib.error.HTTPError as e:
            return _Resp(e.code, e.read(), dict(e.headers))
        except urllib.error.URLError as e:
            raise ConnectionError(f"{url} - {e.reason}") from e

    # ---- envio de sonda (orchestrator) ----
    def send_ctx(self, ctx: ProbeContext) -> _Resp:
        s = self.settings
        method = ctx.target.method
        headers = dict(ctx.headers)
        if ctx.target.cookies:
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in ctx.target.cookies.items())

        data = None
        params = None
        if method == "GET":
            params = ctx.params
        else:
            if ctx.body is not None:
                data = ctx.body.encode() if isinstance(ctx.body, str) else ctx.body
            elif ctx.params:
                data = urllib.parse.urlencode(ctx.params).encode()
                headers.setdefault("Content-Type",
                                   "application/x-www-form-urlencoded")
            if headers.get("Transfer-Encoding") == "chunked" and data:
                return self._send_chunked(ctx, headers, data)

        full_url = ctx.target.url
        if params:
            sep = "&" if "?" in full_url else "?"
            full_url = full_url + sep + urllib.parse.urlencode(params)
        req = urllib.request.Request(full_url, data=data, headers=headers,
                                     method=method)
        try:
            resp = self._opener().open(req, timeout=s.limits.timeout)
            return _Resp(resp.status, resp.read(), dict(resp.headers))
        except urllib.error.HTTPError as e:
            return _Resp(e.code, e.read(), dict(e.headers))
        except urllib.error.URLError as e:
            raise ConnectionError(f"{ctx.target.url} - {e.reason}") from e

    # ---- Transfer-Encoding: chunked (urllib nao suporta) ----
    def _send_chunked(self, ctx, headers, data) -> _Resp:
        parts = urllib.parse.urlsplit(ctx.target.url)
        path = parts.path + ("?" + parts.query if parts.query else "")
        proxy = self._proxy()
        timeout = self.settings.limits.timeout
        conn = self._conn(parts, proxy, timeout)
        if proxy and proxy.startswith("http://"):
            conn.putrequest(ctx.target.method, ctx.target.url, skip_host=True)
            conn.putheader("Host", parts.netloc)
        else:
            conn.putrequest(ctx.target.method, path)
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        i = 0
        while i < len(data):
            n = random.randint(3, 12)
            chunk = data[i:i + n]
            conn.send(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
            i += n
        conn.send(b"0\r\n\r\n")
        resp = conn.getresponse()
        body = resp.read()
        rh = dict(resp.getheaders())
        status = resp.status
        conn.close()
        return _Resp(status, body, rh)

    @staticmethod
    def _conn(parts, proxy, timeout):
        if proxy and proxy.startswith("http://"):
            pp = urllib.parse.urlsplit(proxy)
            return http.client.HTTPConnection(pp.netloc, timeout=timeout)
        if parts.scheme == "https":
            ctx = ssl._create_unverified_context()
            return http.client.HTTPSConnection(parts.netloc, timeout=timeout,
                                               context=ctx)
        return http.client.HTTPConnection(parts.netloc, timeout=timeout)