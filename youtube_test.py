#!/usr/bin/env python3
"""YouTube throughput test for Xray-verified proxy configs.

Reads results/xray_checked*.txt, opens each candidate through a temporary Xray
SOCKS5 inbound, asks yt-dlp for a real YouTube video stream URL through that
proxy, then downloads a bounded byte range from googlevideo.com through the
same proxy. Ordinary result files are never filtered or rewritten.
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import checker

OUT = checker.OUT_DIR
XRAY_BIN = os.getenv("XRAY_BIN", "") or checker.XRAY_BIN or shutil.which("xray") or ""
CURL = shutil.which("curl") or ""
YT_DLP = shutil.which("yt-dlp") or ""
VIDEO_URL = os.getenv("YOUTUBE_TEST_VIDEO", "https://www.youtube.com/watch?v=aqz-KE-bpKQ")
TEST_BYTES = max(512_000, int(os.getenv("YOUTUBE_TEST_BYTES", "4000000")))
MAX_WORKERS = max(1, int(os.getenv("YOUTUBE_WORKERS", "6")))
START_TIMEOUT = max(3.0, float(os.getenv("YOUTUBE_START_TIMEOUT", "8")))
EXTRACT_TIMEOUT = max(8.0, float(os.getenv("YOUTUBE_EXTRACT_TIMEOUT", "35")))
DOWNLOAD_TIMEOUT = max(8.0, float(os.getenv("YOUTUBE_DOWNLOAD_TIMEOUT", "30")))
FAST_MIN_MBPS = max(0.0, float(os.getenv("YOUTUBE_FAST_MIN_MBPS", "8")))
FAST_LIMIT = max(1, int(os.getenv("YOUTUBE_FAST_LIMIT", "100")))
BASE_PORT = int(os.getenv("YOUTUBE_BASE_PORT", "30000"))
LOCK = threading.Lock()
PORTS = iter(range(BASE_PORT, BASE_PORT + 2000))


def read_candidates() -> list[str]:
    files = [OUT / "xray_checked.txt"]
    files += sorted(OUT.glob("xray_checked_[0-9]*.txt"), key=lambda p: int(re.search(r"_(\d+)", p.stem).group(1)))
    lines: list[str] = []
    seen: set[str] = set()
    for path in files:
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = checker.parse_line(raw)
            if not line:
                continue
            # Exact URI duplicate suppression. IP-level dedupe is performed after DNS.
            key = line.split("#", 1)[0]
            if key not in seen:
                seen.add(key)
                lines.append(line)
    return lines


def wait_port(port: int, proc: subprocess.Popen) -> bool:
    until = time.monotonic() + START_TIMEOUT
    while time.monotonic() < until:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def extract_video_url(proxy: str) -> str | None:
    # yt-dlp performs YouTube page/player requests through the proxy as well.
    cmd = [
        YT_DLP, "--proxy", proxy, "--no-playlist", "--no-warnings", "--quiet",
        "--socket-timeout", "12", "--retries", "1", "--extractor-retries", "1",
        "-f", "bestvideo[height<=1080][protocol^=https]/best[height<=1080]/best",
        "--get-url", VIDEO_URL,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=EXTRACT_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None
    for candidate in (p.stdout or "").splitlines():
        candidate = candidate.strip()
        parsed = urlsplit(candidate)
        if parsed.scheme == "https" and parsed.hostname and parsed.hostname.endswith("googlevideo.com"):
            return candidate
    return None


def measure_download(proxy: str, media_url: str) -> dict | None:
    end = TEST_BYTES - 1
    fmt = "\nYT_RESULT:%{http_code} %{size_download} %{time_starttransfer} %{time_total}"
    cmd = [
        CURL, "--silent", "--show-error", "--location", "--proxy", proxy,
        "--connect-timeout", "10", "--max-time", str(DOWNLOAD_TIMEOUT),
        "--range", f"0-{end}", "--max-filesize", str(TEST_BYTES + 65536),
        "--output", os.devnull, "--write-out", fmt, media_url,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT + 4)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"YT_RESULT:(\d{3})\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", p.stdout or "")
    if not m:
        return None
    code, size, ttfb, total = int(m.group(1)), float(m.group(2)), float(m.group(3)), float(m.group(4))
    if code not in (200, 206) or size < min(TEST_BYTES * 0.8, 1_000_000):
        return None
    transfer = max(0.05, total - ttfb)
    return {
        "downloaded_bytes": int(size),
        "ttfb_seconds": round(ttfb, 3),
        "download_seconds": round(transfer, 3),
        "speed_mbps": round(size * 8 / 1_000_000 / transfer, 2),
    }


def test_one(line: str) -> dict | None:
    outbound = checker.build_outbound(line)
    if not outbound:
        return None
    with LOCK:
        port = next(PORTS)
    proxy = f"socks5h://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="youtube_xray_") as td:
        cfg = Path(td) / "xray.json"
        cfg.write_text(json.dumps(checker.xray_config(port, outbound)), encoding="utf-8")
        try:
            proc = subprocess.Popen(
                [XRAY_BIN, "run", "-c", str(cfg)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError:
            return None
        try:
            if not wait_port(port, proc):
                return None
            media_url = extract_video_url(proxy)
            if not media_url:
                return None
            result = measure_download(proxy, media_url)
            if not result:
                return None
            host, _ = checker.extract_host_port(line)
            return {
                "line": line,
                "ip": checker.resolve_public_ip_sync(host) if hasattr(checker, "resolve_public_ip_sync") else "",
                "scheme": checker.get_scheme(line),
                "country": checker.detect_country(line),
                **result,
            }
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)


def apply_us_ca_cap(rows: list[dict], share: float = 0.25) -> list[dict]:
    """Keep the project's US+CA ceiling in this additional output list too."""
    chosen: list[dict] = []
    north_america = 0
    for row in rows:
        is_na = row.get("country") in {"US", "CA"}
        total_after = len(chosen) + 1
        na_after = north_america + int(is_na)
        if is_na and na_after / total_after > share:
            continue
        chosen.append(row)
        north_america = na_after
    return chosen


def write_lines(path: Path, rows: list[dict]) -> None:
    checker.atomic_write_text(path, "\n".join(r["line"] for r in rows) + ("\n" if rows else ""))


def main() -> int:
    if not XRAY_BIN or not Path(XRAY_BIN).is_file():
        raise SystemExit("YouTube-тест: не найден XRAY_BIN")
    if not CURL or not YT_DLP:
        raise SystemExit("YouTube-тест: нужны curl и yt-dlp (pip install yt-dlp PySocks)")
    candidates = read_candidates()
    if not candidates:
        print("YouTube-тест: xray_checked*.txt пусты; YouTube-файлы очищены")
        write_lines(OUT / "youtube_checked.txt", [])
        write_lines(OUT / "youtube_fast.txt", [])
        checker.atomic_write_text(OUT / "youtube_stats.json", json.dumps({"candidates": 0, "passed": 0}, indent=2))
        return 0

    print(f"YouTube Speed Test: кандидатов Xray checked: {len(candidates)}; загрузка до {TEST_BYTES / 1_000_000:.1f} MB, workers={MAX_WORKERS}")
    results: list[dict] = []
    failures = 0
    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(test_one, line): line for line in candidates}
        for n, future in enumerate(cf.as_completed(futures), 1):
            try:
                row = future.result()
            except Exception:
                row = None
            if row:
                results.append(row)
            else:
                failures += 1
            if n % 10 == 0 or n == len(futures):
                print(f"  YouTube: {n}/{len(futures)} | успешно: {len(results)} | не прошли: {failures}", flush=True)

    # One configuration per server IP where resolvable; otherwise exact URI uniqueness.
    results.sort(key=lambda r: (-r["speed_mbps"], r["ttfb_seconds"]))
    unique: list[dict] = []
    seen_ip: set[str] = set()
    seen_uri: set[str] = set()
    for row in results:
        host, _ = checker.extract_host_port(row["line"])
        try:
            ip = socket.gethostbyname(host) if host else ""
            if not ipaddress.ip_address(ip).is_global:
                ip = ""
        except Exception:
            ip = ""
        key = row["line"].split("#", 1)[0]
        if ip and ip in seen_ip:
            continue
        if key in seen_uri:
            continue
        if ip:
            seen_ip.add(ip)
        seen_uri.add(key)
        row["ip"] = ip
        unique.append(row)

    youtube_checked = apply_us_ca_cap(unique, checker.MAX_US_CA_SHARE)
    fast = apply_us_ca_cap(
        [r for r in youtube_checked if r["speed_mbps"] >= FAST_MIN_MBPS],
        checker.MAX_US_CA_SHARE,
    )[:FAST_LIMIT]
    write_lines(OUT / "youtube_checked.txt", youtube_checked)
    write_lines(OUT / "youtube_fast.txt", fast)
    stats = {
        "video_url": VIDEO_URL,
        "test_bytes_target": TEST_BYTES,
        "workers": MAX_WORKERS,
        "fast_min_mbps": FAST_MIN_MBPS,
        "fast_limit": FAST_LIMIT,
        "candidates": len(candidates),
        "passed_before_ip_dedupe": len(results),
        "passed_unique_before_us_ca_cap": len(unique),
        "youtube_checked_count": len(youtube_checked),
        "fast_count": len(fast),
        "us_ca_share_limit": checker.MAX_US_CA_SHARE,
        "failed": failures,
        "results": [{k: v for k, v in r.items() if k != "line"} for r in unique],
    }
    checker.atomic_write_text(OUT / "youtube_stats.json", json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"YouTube Speed Test завершён: youtube_checked={len(youtube_checked)}, youtube_fast={len(fast)} (>= {FAST_MIN_MBPS:g} Мбит/с)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
