#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сборщик VLESS Reality для проверки SNI и инфраструктуры белых списков.

Источники: sources.txt / sources_ai.txt, публичные GitHub-репозитории и code search,
прямые HTTP(S)-списки и публичные Telegram preview-каналы.

Скрипт также предоставляет общие функции для similar.py.
Python 3.10+. Внешние Python-зависимости необязательны; geoip2 нужен только для MMDB.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import html
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse as up
import urllib.request as ur
import zipfile
import tarfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DEFAULT_RESULTS = ROOT / "results" / "collect"
POOL_DEFAULT = ROOT / "work" / "pool.txt"
SOURCES_FILE = ROOT / "sources.txt"
UA = "Mozilla/5.0 (compatible; whitelist-research-collector/2.0)"
VLESS_RE = re.compile(r"vless://[^\s<>\"'`]+", re.I)
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
SID_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){0,8}$")
TEXT_EXT = {"", ".txt", ".md", ".json", ".yaml", ".yml", ".conf", ".sub", ".list", ".jsonc"}
GOOD_NAME = re.compile(r"reality|vless|white|sni|ru|sub|mix|all|config|vpn|v2ray|xray", re.I)

# Основные домены и дополнительные домены из ai_domains.txt / my_domains.txt.
TIER1 = [
    "vk.com", "vk.ru", "vkvideo.ru", "userapi.com", "vkuser.net",
    "yandex.ru", "yandex.com", "yandex.net", "ya.ru", "yastatic.net", "yandexcloud.net",
    "max.ru", "oneme.ru", "ozon.ru", "ozone.ru",
]
TIER2 = [
    "ok.ru", "mail.ru", "mycdn.me", "dzen.ru", "kinopoisk.ru", "rutube.ru",
    "2gis.com", "tbank.ru", "tinkoff.ru", "sber.ru",
]
RU_TLDS = (".ru", ".su", ".xn--p1ai")
for _f in (ROOT / "ai_domains.txt", ROOT / "my_domains.txt"):
    if _f.exists():
        for _line in _f.read_text(encoding="utf-8", errors="ignore").splitlines():
            _d = _line.strip().lower().rstrip(".")
            if _d and not _d.startswith("#") and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{1,248}[a-z0-9])?", _d):
                TIER2.append(_d)

# Лимиты. Основные списки не превышают 600 записей.
MAX_TOTAL = 600
MAX_CANDIDATES = 600
MAX_NOTCP_RU = 300
MAX_PER_IP = 2
MAX_XRAY_TEST = 1800
MAX_SINGBOX_TEST = 1800
CORE_WORKERS = 20
TCP_WORKERS = 100
DNS_WORKERS = 64
TCP_TIMEOUT = 4.0
TCP_RETRY_TIMEOUT = 7.0
CORE_START_TIMEOUT = 5.0
CORE_CHECK_TIMEOUT = 13.0
SPEED_TIMEOUT = 7
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=2000000"
MAX_SPEED_TEST = 300  # speed-test only top 300 servers to keep bandwidth/time bounded
EXIT_URLS = ["https://www.cloudflare.com/cdn-cgi/trace", "https://api64.ipify.org"]
EXIT_TIMEOUTS = [7, 5]
NORTH_AMERICA_SHARE = 0.25  # США + Канада вместе, максимум четверть каждого итогового списка.

# Search breadth. The GitHub code-search endpoint has a strict authenticated rate limit.
DISCOVER_DAYS = 365
MAX_DISCOVER = 120
DISCOVER_PAGES = 2
GH_REPO_SEARCH_DELAY_AUTH = 2.1  # GitHub repository search: up to 30/min when authenticated
GH_REPO_SEARCH_DELAY_UNAUTH = 6.5  # conservative unauthenticated search pacing
FILES_PER_REPO = 100
FILES_PER_FOUND = 60
GH_CODE_PAGES = 3
GH_CODE_REQUEST_DELAY = 6.5  # <= 10 code-search requests/minute
MAX_URLS = 5000
MAX_LINKS = 250000
TG_PAGES = 10
TG_MAX_AGE_DAYS = 30
GEO_LANG = "en"

DEFAULT_DISCOVER = [
    "vless reality", "vless reality russia", "vless whitelist", "v2ray configs",
    "xray subscription", "vless subscription", "proxy subscription vless",
    "белые списки vless", "vless reality config", "sing-box vless reality",
]
DEFAULT_SEARCH = [
    '"security=reality" "sni=vk.com"',
    '"security=reality" "sni=vk.ru"',
    '"security=reality" "sni=yandex.ru"',
    '"security=reality" "sni=max.ru"',
    '"security=reality" "sni=ozon.ru"',
    '"security=reality" "sni=ya.ru"',
    '"security=reality" "sni=userapi.com"',
]

_print_lock = threading.Lock()
_geo_cache: dict[str, dict[str, Any]] = {}
try:
    import tldextract  # type: ignore
    # Use the package's bundled Public Suffix List snapshot; never download at runtime.
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:
    _TLD_EXTRACTOR = None


def log(*parts: Any) -> None:
    with _print_lock:
        print(*parts, file=sys.stderr, flush=True)


def atomic_write(path: Path, data: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    mode = "wb" if isinstance(data, bytes) else "w"
    kwargs = {} if isinstance(data, bytes) else {"encoding": "utf-8", "newline": "\n"}
    with open(tmp, mode, **kwargs) as f:
        f.write(data)
    tmp.replace(path)


def http_text(url: str, headers: dict[str, str] | None = None, data: bytes | None = None,
              timeout: float = 25, max_bytes: int = 8_000_000, retries: int = 2) -> str | None:
    h = {"User-Agent": UA}
    h.update(headers or {})
    for attempt in range(retries + 1):
        try:
            req = ur.Request(url, data=data, headers=h)
            with ur.urlopen(req, timeout=timeout) as response:
                payload = response.read(max_bytes)
                return payload.decode("utf-8", "ignore")
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410, 451):
                return None
            if exc.code == 429:
                wait = int(exc.headers.get("Retry-After", "15") or 15)
                log(f"  ! HTTP 429 для {url[:90]} — пауза {min(wait, 120)} с")
                time.sleep(min(wait, 120))
            elif exc.code in (403, 422):
                log(f"  ! HTTP {exc.code} для {url[:100]}")
                return None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            if attempt == retries:
                log(f"  ! Ошибка загрузки {url[:100]}: {type(exc).__name__}")
        time.sleep(1.0 * (attempt + 1))
    return None


def gh_api(url: str, token: str | None) -> dict[str, Any] | None:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    text = http_text(url, headers=headers, timeout=25, max_bytes=15_000_000, retries=2)
    if not text:
        return None
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        return None


def _read_sources(path: Path, sources: dict[str, list[str]], stats: Counter | None = None) -> None:
    if not path.exists():
        return
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        kind, value = line.split(":", 1)
        kind, value = kind.strip().lower(), value.strip()
        if kind in sources and value:
            sources[kind].append(value)
        elif stats is not None:
            stats["invalid_source_lines"] += 1
            log(f"  ! {path.name}:{line_no}: неизвестный тип источника {kind!r}")


def load_sources() -> dict[str, list[str]]:
    src = {k: [] for k in ("discover", "repo", "search", "url", "tg")}
    _read_sources(SOURCES_FILE, src)
    # Sources from optional AI advisor are additive, never replace defaults.
    _read_sources(ROOT / "sources_ai.txt", src)
    if not src["discover"]:
        src["discover"] = list(DEFAULT_DISCOVER)
    if not src["search"]:
        src["search"] = list(DEFAULT_SEARCH)
    for key in src:
        src[key] = list(dict.fromkeys(src[key]))
    return src


def _normalise_b64(text: str) -> str:
    s = re.sub(r"\s+", "", text)
    if len(s) < 40 or not re.fullmatch(r"[A-Za-z0-9+/_=-]+", s):
        return ""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", "ignore")
    except Exception:
        return ""


def extract_links(text: str, unescape_html: bool = False) -> list[str]:
    text = html.unescape(text) if unescape_html else text.replace("&amp;", "&")
    # Subscriptions often contain a Base64-encoded text with many vless:// lines.
    if "vless://" not in text:
        decoded = _normalise_b64(text)
        if decoded:
            text = decoded
    out = []
    for match in VLESS_RE.findall(text):
        link = match.rstrip(".,;)]}»\"'")
        if len(link) <= 8192:
            out.append(link)
    return out


def public_host(host: str | None) -> bool:
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        host = host.rstrip(".")
        if len(host) > 253 or "." not in host or host.lower() in {"localhost", "localhost.localdomain"}:
            return False
        try:
            host.encode("idna")
        except UnicodeError:
            return False
        labels = host.split(".")
        return all(1 <= len(label) <= 63 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) for label in labels)


def resolve(host: str) -> str | None:
    """Return one globally routable address only. Avoid private/link-local DNS targets."""
    try:
        values = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return None
    public = []
    for item in values:
        raw_ip = item[4][0]
        try:
            addr = ipaddress.ip_address(raw_ip.split("%", 1)[0])
            if addr.is_global:
                public.append(str(addr))
        except ValueError:
            continue
    if not public:
        return None
    # Prefer IPv4 for maximum compatibility; IPv6 remains supported when no IPv4 exists.
    return next((ip for ip in public if ipaddress.ip_address(ip).version == 4), public[0])


def norm_pbk(value: str) -> str:
    return value.replace(" ", "+").strip().rstrip("=").replace("+", "-").replace("/", "_")


def match_tier(sni: str) -> int:
    value = (sni or "").lower().rstrip(".")
    for tier, domains in ((1, TIER1), (2, TIER2)):
        if any(value == domain or value.endswith("." + domain) for domain in domains):
            return tier
    return 3 if value.endswith(RU_TLDS) else 0


def parse_vless(link: str, keep_other: bool = False, require_reality: bool = True,
                why: Counter | None = None) -> dict[str, Any] | None:
    """Разбирает VLESS URI. require_reality=True — режим коллектора белых списков."""
    def reject(reason: str) -> None:
        if why is not None:
            why[reason] += 1

    link = link.strip().replace("&amp;", "&")
    try:
        uri = up.urlsplit(link)
        port = uri.port
        host = uri.hostname
    except ValueError:
        reject("bad_url")
        return None
    if uri.scheme.lower() != "vless" or not uri.username or not port or not (1 <= port <= 65535):
        reject("bad_url")
        return None
    host = (host or "").strip().lower()
    uuid = up.unquote(uri.username).lower()
    if not public_host(host):
        reject("bad_host")
        return None
    if not UUID_RE.fullmatch(uuid):
        reject("bad_uuid")
        return None
    q: dict[str, str] = {}
    for key, value in up.parse_qsl(uri.query, keep_blank_values=True):
        q[key.lower()] = value
    sec = q.get("security", "").lower()
    if sec not in ({"reality"} if require_reality else {"reality", "tls"}):
        reject("not_supported_security")
        return None
    if q.get("encryption", "none").lower() not in ("", "none"):
        reject("unsupported_encryption")
        return None
    pbk = norm_pbk(q.get("pbk", q.get("publickey", "")))
    sid = q.get("sid", "").lower()
    sni = (q.get("sni") or q.get("servername") or q.get("peer") or "").strip().lower()
    if sec == "reality":
        if not PBK_RE.fullmatch(pbk) or not SID_RE.fullmatch(sid):
            reject("bad_reality_key_or_sid")
            return None
        if not sni:
            reject("missing_sni")
            return None
    elif not sni:
        sni = host if not is_ip_literal(host) else ""
    tier = match_tier(sni)
    if not keep_other and require_reality and tier == 0:
        reject("sni_not_whitelist")
        return None
    transport = (q.get("type") or "tcp").lower()
    if transport == "raw":
        transport = "tcp"
    clean = link.split("#", 1)[0]
    # Keep query intact except canonicalising pbk. A normalized URI is easier to import.
    if sec == "reality" and pbk != q.get("pbk", ""):
        clean = re.sub(r"(?i)(?<=[?&])(?:pbk|publickey)=[^&#]*", "pbk=" + up.quote(pbk, safe="-_"), clean)
    return {
        "base": clean, "q": q, "host": host, "port": int(port), "uuid": uuid,
        "sni": sni, "security": sec, "pbk": pbk, "sid": sid,
        "type": transport, "tier": tier, "flow": q.get("flow", ""),
        "fp": q.get("fp", "chrome"), "source_link": link,
    }


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False



def registered_domain(host: str) -> str:
    """Return eTLD+1 using the bundled Public Suffix List; safe fallback if unavailable."""
    value = (host or "").lower().rstrip(".")
    if not value or is_ip_literal(value):
        return ""
    if _TLD_EXTRACTOR is not None:
        try:
            result = _TLD_EXTRACTOR(value)
            return result.top_domain_under_public_suffix or value
        except Exception:
            pass
    labels = value.split(".")
    # Conservative fallback for common multi-label suffixes.
    suffixes = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "com.br",
                "com.tr", "com.ua", "co.jp", "co.kr", "co.in", "co.za", "com.cn", "com.hk",
                "com.sg", "com.tw", "com.mx", "com.ar", "net.ru", "org.ru", "com.ru",
                "msk.ru", "spb.ru", "pp.ru", "co.il", "com.pl", "com.ro", "com.vn"}
    if len(labels) <= 2:
        return value
    suffix2 = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix2 in suffixes else suffix2

def config_key(c: dict[str, Any]) -> tuple[Any, ...]:
    """Dedup only genuinely identical connection configs; include all material Reality fields."""
    q = c.get("q", {})
    important = ("path", "host", "servicename", "mode", "headertype", "seed", "spx",
                 "alpn", "encryption", "extra", "ed", "eh", "quicsecurity", "key", "authority")
    return (
        c.get("host"), c.get("port"), c.get("uuid"), c.get("security"), c.get("pbk"),
        c.get("sid"), c.get("sni"), c.get("type"), c.get("flow"), c.get("fp"),
        tuple((key, q.get(key, "")) for key in important),
    )


def tcp_ping(c: dict[str, Any], timeout: float = TCP_TIMEOUT) -> float | None:
    ip = c.get("ip") or c.get("host")
    started = time.monotonic()
    try:
        with socket.create_connection((ip, int(c["port"])), timeout=timeout):
            return (time.monotonic() - started) * 1000.0
    except OSError:
        return None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _xray_stream(c: dict[str, Any]) -> dict[str, Any] | None:
    """Build a current Project X streamSettings object.

    Project X now uses streamSettings.method (not the legacy network field).
    The former HTTP/H2 transport has been removed from Xray; those links may
    still be tested by sing-box, but must not be sent to Xray as if supported.
    """
    q, t = c.get("q", {}), c.get("type", "tcp")
    security = c.get("security", "reality")
    # REALITY is supported only with RAW, XHTTP and gRPC.
    if security == "reality" and t not in {"tcp", "xhttp", "splithttp", "grpc"}:
        return None
    # The old HTTP/H2 transport is no longer a valid Xray transport method.
    if t in {"http", "h2", "quic"}:
        return None
    method_map = {
        "tcp": "raw", "raw": "raw", "xhttp": "xhttp", "splithttp": "xhttp",
        "grpc": "grpc", "ws": "websocket", "websocket": "websocket",
        "httpupgrade": "httpupgrade", "kcp": "mkcp",
    }
    method = method_map.get(t)
    if method is None:
        return None
    path, host = q.get("path", "") or "/", q.get("host", "")
    user = {"id": c["uuid"], "encryption": "none"}
    if c.get("flow"):
        user["flow"] = c["flow"]
    stream: dict[str, Any] = {"method": method, "security": security}
    if security == "reality":
        stream["realitySettings"] = {
            "serverName": c.get("sni") or c["host"], "fingerprint": c.get("fp") or "chrome",
            "publicKey": c["pbk"], "shortId": c.get("sid", ""), "spiderX": q.get("spx", ""),
        }
    elif security == "tls":
        stream["tlsSettings"] = {"serverName": c.get("sni") or c["host"], "fingerprint": c.get("fp") or "chrome"}
        if q.get("alpn"):
            stream["tlsSettings"]["alpn"] = [v.strip() for v in q["alpn"].split(",") if v.strip()]

    if method == "raw":
        raw_settings: dict[str, Any] = {"header": {"type": "none"}}
        if q.get("headertype", "").lower() == "http":
            headers = [v.strip() for v in host.split(",") if v.strip()]
            request: dict[str, Any] = {"path": [path]}
            if headers:
                request["headers"] = {"Host": headers}
            raw_settings["header"] = {"type": "http", "request": request}
        stream["rawSettings"] = raw_settings
    elif method == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("servicename", ""), "multiMode": q.get("mode") == "multi"}
    elif method == "xhttp":
        xsettings: dict[str, Any] = {"path": path, "mode": q.get("mode") or "auto"}
        if host:
            xsettings["host"] = host
        if q.get("extra"):
            try:
                xsettings["extra"] = json.loads(q["extra"])
            except json.JSONDecodeError:
                return None
        stream["xhttpSettings"] = xsettings
    elif method == "websocket":
        stream["wsSettings"] = {"path": path, "headers": ({"Host": host} if host else {})}
    elif method == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host}
    elif method == "mkcp":
        stream["kcpSettings"] = {"header": {"type": q.get("headertype") or "none"}, "seed": q.get("seed", "")}

    return {"protocol": "vless", "settings": {"vnext": [{
        "address": c.get("ip") or c["host"], "port": int(c["port"]), "users": [user]}]}, "streamSettings": stream}


def _singbox_outbound(c: dict[str, Any]) -> dict[str, Any] | None:
    q, t = c.get("q", {}), c.get("type", "tcp")
    security = c.get("security", "reality")
    # Current sing-box V2Ray transports are HTTP, WS, QUIC, gRPC and HTTPUpgrade;
    # it has no generic TCP or mKCP transport. XHTTP is not mapped here.
    if t in ("xhttp", "splithttp", "kcp"):
        return None
    if t not in {"tcp", "ws", "grpc", "httpupgrade", "http", "h2", "quic"}:
        return None
    # A fake HTTP header on Xray TCP is not the same as sing-box's HTTP transport.
    if t == "tcp" and q.get("headertype", "").lower() == "http":
        return None
    # REALITY's documented Xray transport combinations are RAW, XHTTP and gRPC.
    # sing-box can test only RAW/TCP and gRPC among those mappings.
    if security == "reality" and t not in {"tcp", "grpc"}:
        return None
    outbound: dict[str, Any] = {
        "type": "vless", "tag": "proxy", "server": c.get("ip") or c["host"],
        "server_port": int(c["port"]), "uuid": c["uuid"],
    }
    if c.get("flow"):
        outbound["flow"] = c["flow"]
    if c.get("security") in ("reality", "tls"):
        tls: dict[str, Any] = {
            "enabled": True,
            "server_name": c.get("sni") or c["host"],
            "utls": {"enabled": True, "fingerprint": c.get("fp") or "chrome"},
        }
        if q.get("alpn"):
            tls["alpn"] = [v for v in q["alpn"].split(",") if v]
        if c.get("security") == "reality":
            tls["reality"] = {"enabled": True, "public_key": c["pbk"], "short_id": c.get("sid", "")}
        outbound["tls"] = tls
    path, host = q.get("path", "") or "/", q.get("host", "")
    if t == "ws":
        outbound["transport"] = {"type": "ws", "path": path, "headers": ({"Host": host} if host else {})}
    elif t == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": q.get("servicename", "")}
    elif t == "httpupgrade":
        outbound["transport"] = {"type": "httpupgrade", "path": path, "host": host}
    elif t == "quic":
        # V2Ray QUIC is supported by sing-box but intentionally not by current Xray.
        outbound["transport"] = {"type": "quic"}
    elif t in ("http", "h2"):
        outbound["transport"] = {"type": "http", "path": path, "host": [h.strip() for h in host.split(",") if h.strip()]}
    elif t == "tcp" and q.get("headertype", "").lower() == "http":
        outbound["transport"] = {"type": "http", "path": path, "host": [h.strip() for h in host.split(",") if h.strip()]}
    return outbound


def _core_config(c: dict[str, Any], port: int, core: str) -> dict[str, Any] | None:
    if core == "xray":
        outbound = _xray_stream(c)
        if outbound is None:
            return None
        outbound["tag"] = "proxy"
        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            "routing": {"domainStrategy": "AsIs", "rules": []},
        }
    outbound2 = _singbox_outbound(c)
    if outbound2 is None:
        return None
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "local-socks", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound2, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }


def _curl_via(port: int, url: str, timeout: int, speed: bool = False) -> tuple[str, float]:
    try:
        if speed:
            cmd = ["curl", "-fsS", "--max-time", str(timeout), "--socks5-hostname", f"127.0.0.1:{port}",
                   "-o", os.devnull, "-w", "%{http_code} %{size_download} %{speed_download}", url]
        else:
            cmd = ["curl", "-fsS", "--max-time", str(timeout), "--socks5-hostname", f"127.0.0.1:{port}", url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        return result.stdout.strip(), result.returncode
    except (subprocess.TimeoutExpired, OSError):
        return "", -1


def _exit_info(port: int) -> tuple[str | None, str]:
    for url, timeout in zip(EXIT_URLS, EXIT_TIMEOUTS):
        output, code = _curl_via(port, url, timeout, False)
        if code != 0 or not output:
            continue
        match = re.search(r"^ip=(\S+)", output, re.M) or re.match(r"^\s*([0-9a-fA-F:.]+)\s*$", output)
        if not match:
            continue
        try:
            ip = str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            continue
        cc = re.search(r"^loc=([A-Z]{2})", output, re.M)
        return ip, cc.group(1) if cc else ""
    return None, ""


def probe_core(c: dict[str, Any], binary: str, core: str, measure_speed: bool = True) -> dict[str, Any] | None:
    """Run a local core, perform an actual request through it, return exit IP and speed."""
    if not binary or not shutil.which("curl"):
        return None
    port = _free_port()
    config = _core_config(c, port, core)
    if config is None:
        return None
    proc: subprocess.Popen | None = None
    with tempfile.TemporaryDirectory(prefix=f"{core}-probe-") as temp:
        cfg_path = Path(temp) / "config.json"
        err_path = Path(temp) / "stderr.log"
        cfg_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        try:
            with err_path.open("wb") as err_file:
                command = [binary, "run", "-c", str(cfg_path)] if core == "xray" else [binary, "run", "-c", str(cfg_path)]
                proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=err_file)
            ready = False
            deadline = time.monotonic() + CORE_START_TIMEOUT
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    return None
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.1)
            if not ready:
                return None
            exit_ip, exit_cc = _exit_info(port)
            if not exit_ip:
                return None
            mbps = 0.0
            if measure_speed:
                text, code = _curl_via(port, SPEED_URL, SPEED_TIMEOUT, True)
                if code == 0:
                    try:
                        status, size, speed = text.split()[:3]
                        if status == "200" and float(size) >= 50000:
                            mbps = float(speed) * 8 / 1_000_000
                    except (ValueError, IndexError):
                        pass
            return {"exit_ip": exit_ip, "exit_cc": exit_cc, "mbps": round(mbps, 3)}
        except (OSError, subprocess.SubprocessError):
            return None
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=1.5)
                except Exception:
                    try:
                        proc.kill()
                        proc.wait(timeout=1.5)
                    except Exception:
                        pass


def geo_lookup(ips: set[str] | list[str], mmdb_path: str | None = None) -> dict[str, dict[str, Any]]:
    """Country/city lookup: local MaxMind GeoLite2 if present, then rate-limited ip-api batch fallback."""
    unique = sorted({str(x) for x in ips if x})
    result: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    db_path = Path(mmdb_path or os.environ.get("GEOIP_DB", ROOT / "GeoLite2-City.mmdb"))
    if db_path.exists():
        try:
            import geoip2.database  # type: ignore
            with geoip2.database.Reader(str(db_path)) as reader:
                for ip in unique:
                    try:
                        record = reader.city(ip)
                        country = record.country.name or ""
                        cc = record.country.iso_code or ""
                        city = record.city.name or ""
                        if country or cc:
                            result[ip] = {"country": country, "countryCode": cc, "city": city, "query": ip, "status": "success", "provider": "MaxMind GeoLite2"}
                        else:
                            missing.append(ip)
                    except Exception:
                        missing.append(ip)
        except Exception as exc:
            log(f"! GeoLite2 не прочитана ({type(exc).__name__}); перехожу на IP-API")
            missing = unique[:]
    else:
        missing = unique[:]
    missing = [ip for ip in missing if ip not in result]
    if not missing:
        return result
    log(f"Геолокация: {len(unique) - len(missing)} из локальной базы; {len(missing)} через IP-API")
    # Free ip-api batch endpoint: max 100 items/request and max 15 requests/min.
    # We wait 4.2 sec between requests and respect X-Rl / X-Ttl if present.
    for offset in range(0, len(missing), 100):
        batch = missing[offset:offset + 100]
        body = json.dumps([{"query": ip, "fields": "status,country,countryCode,city,query", "lang": GEO_LANG} for ip in batch]).encode()
        req = ur.Request("http://ip-api.com/batch", data=body,
                         headers={"User-Agent": UA, "Content-Type": "application/json"})
        try:
            with ur.urlopen(req, timeout=40) as response:
                payload = response.read(2_000_000).decode("utf-8", "ignore")
                remaining = response.headers.get("X-Rl")
                ttl = response.headers.get("X-Ttl")
            try:
                rows = json.loads(payload)
            except json.JSONDecodeError:
                rows = []
            for row in rows if isinstance(rows, list) else []:
                if row.get("status") == "success" and row.get("query"):
                    result[row["query"]] = row
            if remaining == "0":
                time.sleep(max(1, min(int(ttl or 60), 120)))
            elif offset + 100 < len(missing):
                time.sleep(4.2)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                wait = int(exc.headers.get("X-Ttl", "60") or 60)
                log(f"! IP-API ограничил запросы; ожидание {wait} с")
                time.sleep(max(5, min(wait, 180)))
                # One retry for this batch after the reset.
                try:
                    with ur.urlopen(req, timeout=40) as response:
                        rows = json.loads(response.read(2_000_000).decode("utf-8", "ignore"))
                    for row in rows if isinstance(rows, list) else []:
                        if row.get("status") == "success" and row.get("query"):
                            result[row["query"]] = row
                except Exception as retry_exc:
                    log(f"! IP-API retry failed: {type(retry_exc).__name__}")
            else:
                log(f"! IP-API HTTP {exc.code}; продолжение без части геоданных")
        except Exception as exc:
            log(f"! IP-API batch failed: {type(exc).__name__}")
    return result


def flag(cc: str) -> str:
    if not re.fullmatch(r"[A-Za-z]{2}", cc or ""):
        return "🏳"
    return "".join(chr(0x1F1E6 + ord(ch.upper()) - 65) for ch in cc)


def make_name(geo: dict[str, Any] | None, fallback_cc: str = "") -> str:
    geo = geo or {}
    country, city = geo.get("country", ""), geo.get("city", "")
    cc = geo.get("countryCode", "") or fallback_cc
    if country:
        return f"{flag(cc)} {country}" + (f", {city}" if city and city != country else "")
    if cc:
        return f"{flag(cc)} {cc}"
    return "🏳 Unknown"


def _discover_repos(queries: list[str], token: str | None, skip: set[str], stats: Counter) -> list[str]:
    since = (datetime.now(timezone.utc) - timedelta(days=DISCOVER_DAYS)).strftime("%Y-%m-%d")
    found: list[str] = []
    for query in queries:
        if len(found) >= MAX_DISCOVER:
            break
        for page in range(1, DISCOVER_PAGES + 1):
            params = up.urlencode({"q": f"{query} pushed:>={since}", "sort": "updated", "order": "desc", "per_page": 100, "page": page})
            data = gh_api("https://api.github.com/search/repositories?" + params, token)
            time.sleep(GH_REPO_SEARCH_DELAY_AUTH if token else GH_REPO_SEARCH_DELAY_UNAUTH)
            if not data:
                stats["github_repo_search_errors"] += 1
                break
            items = data.get("items") or []
            stats["github_repos_seen"] += len(items)
            for item in items:
                name = item.get("full_name")
                if name and not item.get("archived") and name.lower() not in skip and name not in found:
                    found.append(name)
                    if len(found) >= MAX_DISCOVER:
                        break
            if len(items) < 100:
                break
        log(f"  GitHub repos «{query}»: сейчас {len(found)}")
    stats["github_repos_discovered"] = len(found)
    return found[:MAX_DISCOVER]


def _repo_file_urls(repo: str, token: str | None, limit: int, stats: Counter) -> list[str]:
    info = gh_api(f"https://api.github.com/repos/{repo}", token)
    if not info:
        stats["github_repo_info_errors"] += 1
        return []
    branch = info.get("default_branch") or "main"
    encoded_branch = up.quote(branch, safe="")
    tree = gh_api(f"https://api.github.com/repos/{repo}/git/trees/{encoded_branch}?recursive=1", token)
    if not tree:
        stats["github_tree_errors"] += 1
        return []
    if tree.get("truncated"):
        stats["github_truncated_trees"] += 1
    files = []
    for node in tree.get("tree") or []:
        path = node.get("path", "")
        if node.get("type") != "blob" or int(node.get("size") or 0) > 4_000_000:
            continue
        if Path(path).suffix.lower() in TEXT_EXT:
            files.append(path)
    files.sort(key=lambda p: (not bool(GOOD_NAME.search(p)), len(p), p.lower()))
    return [f"https://raw.githubusercontent.com/{repo}/{encoded_branch}/{up.quote(p, safe='/')}" for p in files[:limit]]


def _search_code_files(queries: list[str], token: str | None, stats: Counter) -> list[str]:
    if not token:
        log("! GITHUB_TOKEN не задан — поиск по GitHub Code Search пропущен; repo discovery и прямые repo остаются доступны только если API позволяет")
        stats["github_code_search_skipped_no_token"] = 1
        return []
    urls: list[str] = []
    requests_done = 0
    for query in queries:
        for page in range(1, GH_CODE_PAGES + 1):
            if requests_done >= 20:
                stats["github_code_search_request_cap"] = requests_done
                return list(dict.fromkeys(urls))
            params = up.urlencode({"q": query, "per_page": 100, "page": page})
            data = gh_api("https://api.github.com/search/code?" + params, token)
            requests_done += 1
            stats["github_code_search_requests"] = requests_done
            time.sleep(GH_CODE_REQUEST_DELAY)
            if not data:
                stats["github_code_search_errors"] += 1
                break
            items = data.get("items") or []
            stats["github_code_files_seen"] += len(items)
            for item in items:
                html_url = item.get("html_url", "")
                match = re.match(r"^https://github\.com/([^/]+/[^/]+)/blob/([^/]+)/(.+)$", html_url)
                if match:
                    urls.append(f"https://raw.githubusercontent.com/{match.group(1)}/{up.quote(match.group(2), safe='')}/{up.quote(match.group(3), safe='/')}")
            if len(items) < 100:
                break
        log(f"  GitHub code «{query[:55]}»: файлов собрано {len(set(urls))}")
    return list(dict.fromkeys(urls))


def _fetch_tg(channel: str, stats: Counter) -> list[str]:
    channel = re.sub(r"^(https?://)?(t\.me/(s/)?)?@?", "", channel.strip()).strip("/")
    if not re.fullmatch(r"[A-Za-z0-9_]{4,64}", channel):
        stats["telegram_invalid_channels"] += 1
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=TG_MAX_AGE_DAYS)
    links: list[str] = []
    before: int | None = None
    for _ in range(TG_PAGES):
        url = f"https://t.me/s/{channel}" + (f"?before={before}" if before else "")
        page = http_text(url, timeout=20, max_bytes=5_000_000, retries=1)
        if not page:
            stats["telegram_fetch_errors"] += 1
            break
        chunks = page.split('data-post="')[1:]
        ids: list[int] = []
        oldest: datetime | None = None
        for chunk in chunks:
            match = re.match(r"[\w]+/(\d+)", chunk)
            if not match:
                continue
            post_id = int(match.group(1))
            ids.append(post_id)
            tm = re.search(r'<time[^>]*datetime="([^"]+)"', chunk)
            post_time = None
            if tm:
                try:
                    post_time = datetime.fromisoformat(tm.group(1).replace("Z", "+00:00"))
                except ValueError:
                    pass
            if post_time:
                oldest = post_time if oldest is None else min(oldest, post_time)
            if post_time is None or post_time >= cutoff:
                links.extend(extract_links(chunk, unescape_html=True))
        if not ids or (oldest and oldest < cutoff):
            break
        before = min(ids)
        time.sleep(0.6)
    return links


def _read_urls(urls: list[str], stats: Counter) -> list[str]:
    urls = list(dict.fromkeys(urls))[:MAX_URLS]
    stats["source_urls_to_download"] = len(urls)
    all_links: list[str] = []
    with cf.ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(http_text, url, None, None, 25, 8_000_000, 2): url for url in urls}
        for future in cf.as_completed(futures):
            try:
                text = future.result()
            except Exception as exc:
                stats["source_download_errors"] += 1
                log(f"  ! загрузка источника завершилась ошибкой: {type(exc).__name__}")
                continue
            if text:
                stats["source_files_downloaded"] += 1
                all_links.extend(extract_links(text))
            if len(all_links) >= MAX_LINKS:
                log("! Достигнут предохранительный лимит извлечённых ссылок")
                break
    return all_links[:MAX_LINKS]


def _country_code(c: dict[str, Any], geo: dict[str, dict[str, Any]]) -> str:
    """Return country of the proxy egress, falling back to entry IP only if unknown."""
    if c.get("exit_cc"):
        return str(c["exit_cc"]).upper()
    # If the proxy returned an egress IP but Cloudflare's country tag was absent,
    # use GeoIP for that egress IP. Do not silently classify it by the server IP.
    target_ip = c.get("exit_ip") or c.get("ip", "")
    return str(geo.get(target_ip, {}).get("countryCode", "")).upper()


def _apply_na_cap(items: list[dict[str, Any]], max_items: int, geo: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Keep US+CA <=25%; unknown geography is conservatively counted in the same quota."""
    ordered = sorted(items, key=lambda c: c.get("rank_key", ()))
    normal: list[dict[str, Any]] = []
    restricted: list[dict[str, Any]] = []
    for item in ordered:
        code = _country_code(item, geo)
        if code in {"US", "CA", ""}:
            restricted.append(item)
        else:
            normal.append(item)
    selected = normal[:max_items]
    restricted_added = 0
    for item in restricted:
        if len(selected) >= max_items:
            break
        # Count unresolved IPs as restricted: even if all are US/CA, the final share stays <=25%.
        if (restricted_added + 1) / (len(selected) + 1) <= NORTH_AMERICA_SHARE + 1e-12:
            selected.append(item)
            restricted_added += 1
    return selected, len(restricted) - restricted_added


def _write_lines(path: Path, items: list[dict[str, Any]]) -> None:
    lines = [f"{c['base']}#{up.quote(c.get('name', 'Unknown'))}" for c in items]
    atomic_write(path, "\n".join(lines) + ("\n" if lines else ""))


def write_outputs(out: Path, final: list[dict[str, Any]], candidates: list[dict[str, Any]],
                  notcp: list[dict[str, Any]], stats: Counter, geo: dict[str, dict[str, Any]],
                  pool_count: int) -> None:
    out.mkdir(parents=True, exist_ok=True)
    lists_dir = out / "lists"
    reports_dir = out / "reports"
    checkpoints_dir = out / "checkpoints"
    lists_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    checkpoints_dir.mkdir(parents=True, exist_ok=True)
    for name, subset in (
        ("whitelist.txt", final),
        ("xray_verified.txt", [c for c in final if c.get("xray_ok")]),
        ("singbox_verified.txt", [c for c in final if c.get("singbox_ok")]),
        ("verified_by_both.txt", [c for c in final if c.get("xray_ok") and c.get("singbox_ok")]),
        ("candidates_tcp_only.txt", candidates),
        ("candidates_ruip_notcp.txt", notcp),
    ):
        _write_lines(lists_dir / name, subset)
    all_text = (lists_dir / "whitelist.txt").read_text(encoding="utf-8")
    atomic_write(lists_dir / "whitelist_b64.txt", base64.b64encode(all_text.encode()).decode() + "\n")
    _write_lines(lists_dir / "whitelist_ruip.txt", [c for c in final if geo.get(c.get("ip", ""), {}).get("countryCode") == "RU"])
    # Country distribution is explicit so the geographic cap can be audited.
    dist = Counter(_country_code(c, geo) or "UNKNOWN" for c in final)
    stats["final_country_distribution"] = dict(sorted(dist.items()))
    stats["final_us_ca_share"] = round(sum(dist[x] for x in ("US", "CA")) / len(final), 4) if final else 0
    # Unknown country is counted as restricted by the selector; expose that conservative
    # share separately so the report makes the safety margin visible.
    stats["final_us_ca_plus_unknown_share"] = round(
        (sum(dist[x] for x in ("US", "CA")) + dist.get("UNKNOWN", 0)) / len(final), 4
    ) if final else 0
    stats["pool_links_saved"] = pool_count
    atomic_write(reports_dir / "report.json", json.dumps(dict(stats), ensure_ascii=False, indent=2, default=str) + "\n")
    lines = ["COLLECT REPORT", "", f"Result servers: {len(final)}", f"TCP-only candidates: {len(candidates)}",
             f"RU IP with no TCP from runner: {len(notcp)}", f"Pool links: {pool_count}", "",
             "Statistics:"]
    for key, value in sorted(stats.items()):
        lines.append(f"{key}: {value}")
    atomic_write(reports_dir / "report.txt", "\n".join(lines) + "\n")



def _write_core_checkpoint(out: Path, core: str, successes: dict[tuple[Any, ...], dict[str, Any]],
                           candidates_by_key: dict[tuple[Any, ...], dict[str, Any]], completed: int) -> None:
    checkpoint_dir = out / "checkpoints"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    names = []
    for key in successes:
        candidate = candidates_by_key.get(key)
        if candidate:
            names.append(candidate["base"])
    atomic_write(checkpoint_dir / f"{core}_passed_checkpoint.txt", "\n".join(names) + ("\n" if names else ""))
    atomic_write(checkpoint_dir / f"{core}_progress.json", json.dumps({
        "core": core, "completed": completed, "passed": len(successes),
        "updated_utc": datetime.now(timezone.utc).isoformat(),
    }, ensure_ascii=False, indent=2) + "\n")

def run_collection(args: argparse.Namespace) -> int:
    out = Path(args.out).resolve()
    pool_path = Path(args.pool_out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    pool_path.parent.mkdir(parents=True, exist_ok=True)
    stats: Counter = Counter()
    sources = load_sources()
    token = os.environ.get("GH_SEARCH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    log("[1/7] Источники: GitHub discovery/code, repo, direct URL, Telegram")
    urls = list(sources["url"])
    for repo in sources["repo"]:
        repo_urls = _repo_file_urls(repo, token, FILES_PER_REPO, stats)
        log(f"  repo {repo}: {len(repo_urls)} файлов")
        urls.extend(repo_urls)
        stats["manual_repositories"] += 1
    skip = {r.lower() for r in sources["repo"]}
    repos = _discover_repos(sources["discover"], token, skip, stats)
    with cf.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_repo_file_urls, repo, token, FILES_PER_FOUND, stats) for repo in repos]
        for future in cf.as_completed(futures):
            try:
                urls.extend(future.result())
            except Exception:
                stats["repo_download_errors"] += 1
    urls.extend(_search_code_files(sources["search"], token, stats))
    urls = list(dict.fromkeys(urls))[:MAX_URLS]
    stats["unique_source_urls"] = len(urls)

    log(f"[2/7] Загружаю {len(urls)} файлов")
    raw_links = _read_urls(urls, stats)
    stats["links_from_files"] = len(raw_links)
    for channel in sources["tg"]:
        found = _fetch_tg(channel, stats)
        raw_links.extend(found)
        log(f"  Telegram {channel}: {len(found)} ссылок")
    stats["telegram_channels"] = len(sources["tg"])
    stats["links_total_before_dedup"] = len(raw_links)
    raw_links = list(dict.fromkeys(raw_links))[:MAX_LINKS]
    # This pool deliberately contains all discovered VLESS links, not only whitelist matches.
    atomic_write(pool_path, "\n".join(sorted(raw_links)) + ("\n" if raw_links else ""))
    stats["pool_links"] = len(raw_links)
    log(f"[3/7] Сохранён work/pool.txt: {len(raw_links)} уникальных ссылок")

    why: Counter = Counter()
    candidates_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    for link in raw_links:
        item = parse_vless(link, keep_other=False, require_reality=True, why=why)
        if not item:
            continue
        candidates_by_key.setdefault(config_key(item), item)
    candidates = list(candidates_by_key.values())
    stats["links_rejected_or_non_whitelist"] = sum(why.values())
    stats["unique_reality_whitelist_candidates"] = len(candidates)
    stats["tier_distribution"] = dict(Counter(str(c["tier"]) for c in candidates))
    stats["transport_distribution"] = dict(Counter(c["type"] for c in candidates))
    log(f"[4/7] Подходящих уникальных Reality: {len(candidates)}; DNS...")

    hosts = sorted({c["host"] for c in candidates if not is_ip_literal(c["host"])})
    with cf.ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:
        resolved = dict(zip(hosts, executor.map(resolve, hosts)))
    good: list[dict[str, Any]] = []
    bad_dns: list[dict[str, Any]] = []
    for c in candidates:
        ip = c["host"] if is_ip_literal(c["host"]) else resolved.get(c["host"])
        if not ip:
            bad_dns.append(c)
            continue
        try:
            if not ipaddress.ip_address(ip).is_global:
                bad_dns.append(c)
                continue
        except ValueError:
            bad_dns.append(c)
            continue
        good.append(dict(c, ip=ip))
    stats["dns_ok"] = len(good)
    stats["dns_failed_or_non_global"] = len(bad_dns)
    log(f"  DNS успешно: {len(good)}; не прошли / не global: {len(bad_dns)}")

    log(f"[5/7] TCP-проверка {len(good)} адресов")
    with cf.ThreadPoolExecutor(max_workers=TCP_WORKERS) as executor:
        ping_values = list(executor.map(tcp_ping, good))
    dead_indices = [i for i, value in enumerate(ping_values) if value is None]
    if dead_indices:
        with cf.ThreadPoolExecutor(max_workers=TCP_WORKERS) as executor:
            retry_values = list(executor.map(lambda i: tcp_ping(good[i], TCP_RETRY_TIMEOUT), dead_indices))
        recovered = 0
        for idx, value in zip(dead_indices, retry_values):
            ping_values[idx] = value
            recovered += value is not None
        stats["tcp_recovered_on_retry"] = recovered
    alive: list[dict[str, Any]] = []
    dead: list[dict[str, Any]] = []
    for c, ping in zip(good, ping_values):
        if ping is None:
            dead.append(c)
        else:
            alive.append(dict(c, ms=round(float(ping), 2)))
    stats["tcp_ok"] = len(alive)
    stats["tcp_no_answer_from_runner"] = len(dead)
    # Tier 1, then Tier 2, then Russian TLDs. Do not treat all non-zero tiers as equal.
    alive.sort(key=lambda c: (c["tier"], c["ms"], c["host"], c["port"]))
    log(f"  TCP ответили: {len(alive)}; без ответа: {len(dead)}")

    xray_bin = shutil.which(args.xray or os.environ.get("XRAY_BIN") or "xray") if not args.no_xray else None
    singbox_bin = shutil.which(args.sing_box or os.environ.get("SING_BOX_BIN") or "sing-box") if not args.no_singbox else None
    if not shutil.which("curl"):
        log("! curl не найден — проверка через ядра невозможна")
        xray_bin = singbox_bin = None
    stats["xray_available"] = bool(xray_bin)
    stats["singbox_available"] = bool(singbox_bin)
    stats["speed_probe_limit_per_core"] = MAX_SPEED_TEST
    # Save a checkpoint before long-running core probes: even a cancelled Actions job
    # will upload this file as an artifact from the always() step in the workflow.
    checkpoint_dir = out / "checkpoints"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    atomic_write(checkpoint_dir / "tcp_alive_checkpoint.txt", "\n".join(c["base"] for c in alive[:MAX_CANDIDATES]) + ("\n" if alive else ""))
    xray_eligible = [c for c in alive if _core_config(c, 1, "xray") is not None] if xray_bin else []
    singbox_eligible = [c for c in alive if _core_config(c, 1, "singbox") is not None] if singbox_bin else []
    stats["xray_skipped_unsupported_transport"] = len(alive) - len(xray_eligible) if xray_bin else 0
    stats["singbox_skipped_unsupported_transport"] = len(alive) - len(singbox_eligible) if singbox_bin else 0
    xray_targets = xray_eligible[:MAX_XRAY_TEST]
    singbox_targets = singbox_eligible[:MAX_SINGBOX_TEST]
    xray_results: dict[tuple[Any, ...], dict[str, Any]] = {}
    singbox_results: dict[tuple[Any, ...], dict[str, Any]] = {}
    if xray_targets:
        log(f"[6/7] Xray: проверяю {len(xray_targets)} кандидатов")
        key_to_candidate = {config_key(c): c for c in xray_targets}
        with cf.ThreadPoolExecutor(max_workers=CORE_WORKERS) as executor:
            futures = {executor.submit(probe_core, c, xray_bin, "xray", i < MAX_SPEED_TEST): c
                       for i, c in enumerate(xray_targets)}
            completed = 0
            for future in cf.as_completed(futures):
                c = futures[future]
                completed += 1
                try:
                    value = future.result()
                    if value:
                        xray_results[config_key(c)] = value
                except Exception:
                    stats["xray_worker_errors"] += 1
                if completed % 25 == 0 or completed == len(futures):
                    _write_core_checkpoint(out, "xray", xray_results, key_to_candidate, completed)
        stats["xray_ok"] = len(xray_results)
    else:
        stats["xray_ok"] = 0
    if singbox_targets:
        log(f"[7/7] sing-box: проверяю до {len(singbox_targets)} кандидатов")
        key_to_candidate = {config_key(c): c for c in singbox_targets}
        with cf.ThreadPoolExecutor(max_workers=CORE_WORKERS) as executor:
            # To avoid doubling bandwidth, speed-test with Xray when both cores are enabled.
            speed_with_singbox = not bool(xray_bin)
            futures = {executor.submit(probe_core, c, singbox_bin, "singbox", speed_with_singbox and i < MAX_SPEED_TEST): c
                       for i, c in enumerate(singbox_targets)}
            completed = 0
            for future in cf.as_completed(futures):
                c = futures[future]
                completed += 1
                try:
                    value = future.result()
                    if value:
                        singbox_results[config_key(c)] = value
                except Exception:
                    stats["singbox_worker_errors"] += 1
                if completed % 25 == 0 or completed == len(futures):
                    _write_core_checkpoint(out, "singbox", singbox_results, key_to_candidate, completed)
        stats["singbox_ok"] = len(singbox_results)
    else:
        stats["singbox_ok"] = 0

    tested: list[dict[str, Any]] = []
    for c in alive:
        key = config_key(c)
        xr = xray_results.get(key)
        sb = singbox_results.get(key)
        item = dict(c)
        item["xray_ok"] = bool(xr)
        item["singbox_ok"] = bool(sb)
        if xr:
            item.update({"exit_ip": xr["exit_ip"], "exit_cc": xr["exit_cc"], "xray_mbps": xr["mbps"]})
        if sb:
            # Retain separate exit details. Main naming uses Xray exit first, otherwise sing-box.
            item["singbox_exit_ip"] = sb["exit_ip"]
            item["singbox_exit_cc"] = sb["exit_cc"]
            item["singbox_mbps"] = sb["mbps"]
            if not xr:
                item["exit_ip"] = sb["exit_ip"]
                item["exit_cc"] = sb["exit_cc"]
        speeds = [v for v in ((xr or {}).get("mbps", 0), (sb or {}).get("mbps", 0)) if v]
        item["mbps"] = max(speeds, default=0.0)
        item["verified"] = bool(xr or sb)
        item["rank_key"] = (0 if item["verified"] else 1, item["tier"], -item["mbps"], item["ms"], item["host"])
        tested.append(item)
    verified = [c for c in tested if c["verified"]]
    tcp_unverified = [c for c in tested if not c["verified"]]
    # Probe time caps can leave later TCP-alive entries unchecked; keep them in candidate file.
    tested_keys = {config_key(c) for c in tested}
    if len(tested) < len(alive):
        tcp_unverified.extend(c for c in alive if config_key(c) not in tested_keys)
    # Geolocate all items that can possibly enter result/candidate lists, bounded by caps.
    preliminary_candidates = sorted(tcp_unverified, key=lambda c: (c["tier"], c["ms"]))[:MAX_CANDIDATES]
    preliminary_notcp = sorted(dead, key=lambda c: (c["tier"], c["host"]))[:MAX_CANDIDATES * 2]
    # Geolocate every core-verified candidate before ranking/quota selection.
    # A fast server can rank into the final 600 even if it appeared later in TCP order.
    ips = {c["ip"] for c in verified + preliminary_candidates + preliminary_notcp}
    ips |= {c["exit_ip"] for c in verified if c.get("exit_ip")}
    geo = geo_lookup(ips, args.mmdb)
    for c in tested + preliminary_candidates + preliminary_notcp:
        name_ip = c.get("exit_ip") or c["ip"]
        c["name"] = make_name(geo.get(name_ip), c.get("exit_cc", ""))
    # Sort main list by core verification, tier, speed and latency; then cap USA+Canada to 25%.
    for c in verified:
        c["rank_key"] = (0 if c.get("xray_ok") and c.get("singbox_ok") else 1,
                          0 if c.get("xray_ok") else 1, c["tier"], -c["mbps"], c["ms"], c["host"])
    # Enforce the per-address limit after ranking, before the USA+Canada quota.
    diverse_verified: list[dict[str, Any]] = []
    ip_counts: Counter = Counter()
    for item in sorted(verified, key=lambda c: c["rank_key"]):
        if ip_counts[item["ip"]] >= MAX_PER_IP:
            stats["verified_dropped_per_ip"] += 1
            continue
        ip_counts[item["ip"]] += 1
        diverse_verified.append(item)
    final, na_dropped = _apply_na_cap(diverse_verified, MAX_TOTAL, geo)
    stats["north_america_dropped_by_25pct_cap"] = na_dropped
    candidates, candidate_na_dropped = _apply_na_cap(preliminary_candidates, MAX_CANDIDATES, geo)
    stats["candidate_north_america_dropped_by_25pct_cap"] = candidate_na_dropped
    # A special file for Russia-hosted candidates that did not answer from GitHub Actions.
    notcp_ru = [c for c in preliminary_notcp if geo.get(c["ip"], {}).get("countryCode") == "RU"]
    notcp_ru, _ = _apply_na_cap(notcp_ru, MAX_NOTCP_RU, geo)
    stats["final"] = len(final)
    stats["candidates_tcp_only"] = len(candidates)
    stats["candidates_ru_ip_notcp"] = len(notcp_ru)
    stats["xray_verified_in_final"] = sum(c.get("xray_ok", False) for c in final)
    stats["singbox_verified_in_final"] = sum(c.get("singbox_ok", False) for c in final)
    stats["verified_by_both_in_final"] = sum(c.get("xray_ok", False) and c.get("singbox_ok", False) for c in final)
    stats["result_country_distribution"] = dict(Counter(_country_code(c, geo) or "UNKNOWN" for c in final))
    stats["unknown_geo_in_final"] = sum(not _country_code(c, geo) for c in final)
    stats["north_america_quota_includes_unknown_geo"] = True
    write_outputs(out, final, candidates, notcp_ru, stats, geo, len(raw_links))
    log(f"Готово: results/collect — {len(final)} проверенных; {len(candidates)} TCP-кандидатов; {len(notcp_ru)} RU-IP без TCP")
    if not xray_bin and not singbox_bin:
        log("! Ни одно ядро не найдено: основной проверенный список будет пуст, смотри candidates_tcp_only.txt")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Сбор и проверка VLESS Reality с SNI белых списков")
    parser.add_argument("--out", default=str(DEFAULT_RESULTS), help="директория результатов collect")
    parser.add_argument("--pool-out", default=str(POOL_DEFAULT), help="пул сырых ссылок для similar.py")
    parser.add_argument("--xray", default=None, help="путь к Xray")
    parser.add_argument("--sing-box", dest="sing_box", default=None, help="путь к sing-box")
    parser.add_argument("--mmdb", default=None, help="путь к GeoLite2-City.mmdb")
    parser.add_argument("--no-xray", action="store_true")
    parser.add_argument("--no-singbox", action="store_true")
    parser.add_argument("--skip-github-search", action="store_true", help="не выполнять discovery/code search; загрузить только repo/url/tg из sources.txt")
    args = parser.parse_args()
    if args.skip_github_search:
        # Keep manually declared repos/URLs/Telegram; disable dynamic GitHub requests.
        args._skip_github = True
        # Patch only for this run, without changing load_sources defaults permanently.
        original = load_sources
        def local_sources():
            src = original()
            src["discover"] = []
            src["search"] = []
            return src
        globals()["load_sources"] = local_sources
    try:
        raise SystemExit(run_collection(args))
    except KeyboardInterrupt:
        log("Остановлено пользователем. Уже записанный work/pool.txt сохранён.")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
