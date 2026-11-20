#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ищет VLESS Reality/TLS, похожие на серверы из my_working.txt.

Источник кандидатов — work/pool.txt, который независимо формирует collector.py.
Сам сбор источников здесь не запускается: этот скрипт можно выполнять отдельно.
"""
from __future__ import annotations

import argparse
import base64
import collections
import concurrent.futures as cf
import ipaddress
import json
import re
import sys
import os
import shutil
import urllib.parse as up
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import collector as C

ROOT = Path(__file__).resolve().parent
DEFAULT_OUT = ROOT / "results" / "similar"
DEFAULT_POOL = ROOT / "work" / "pool.txt"
DEFAULT_WORKING = ROOT / "my_working.txt"

MAX_TOTAL = 450
MIN_SCORE = 12.0
MAX_PER_IP = 2
MAX_PER_PBK = 12
MAX_PER_FAMILY = 15
MAX_DNS = 20000
MAX_TCP = 8000
MAX_PROBE = 1200
CORE_WORKERS = 20
VERIFIED_BONUS = 8.0
WEIGHTS = {"pbk": 60, "sid": 15, "uuid": 45, "host": 40, "fam": 30, "subnet": 25, "sni": 18}
COMMON_THRESHOLD = 40
NORTH_AMERICA_SHARE = C.NORTH_AMERICA_SHARE


def log(*parts: Any) -> None:
    print(*parts, file=sys.stderr, flush=True)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def subnet24(ip: str) -> str:
    try:
        obj = ipaddress.ip_address(ip)
        return str(ipaddress.ip_network(f"{obj}/{24 if obj.version == 4 else 64}", strict=False))
    except ValueError:
        return ""


def reg_domain(host: str) -> str:
    return C.registered_domain(host)


def _vmess_features(link: str) -> dict[str, Any] | None:
    try:
        encoded = link.split("://", 1)[1].split("#", 1)[0]
        raw = C._normalise_b64(encoded)
        if not raw:
            return None
        d = json.loads(raw)
        return {
            "scheme": "vmess", "base": link.split("#", 1)[0],
            "host": str(d.get("add", "")).lower(), "port": int(d.get("port") or 0),
            "uuid": str(d.get("id", "")).lower(), "pbk": "", "sid": "",
            "sni": str(d.get("sni") or d.get("host") or "").lower(),
            "type": str(d.get("net") or "tcp").lower(), "security": "tls" if d.get("tls") == "tls" else "",
            "flow": "", "fp": str(d.get("fp") or ""), "q": {},
        }
    except (ValueError, TypeError, KeyError):
        return None


def features(link: str) -> dict[str, Any] | None:
    link = link.strip()
    if "://" not in link:
        return None
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        return _vmess_features(link)
    if scheme != "vless":
        return None
    parsed = C.parse_vless(link, keep_other=True, require_reality=False)
    if not parsed:
        return None
    return {
        "scheme": "vless", "base": parsed["base"], "host": parsed["host"],
        "port": parsed["port"], "uuid": parsed["uuid"], "pbk": parsed["pbk"],
        "sid": parsed["sid"], "sni": parsed["sni"], "type": parsed["type"],
        "security": parsed["security"], "flow": parsed["flow"], "fp": parsed["fp"],
        "q": parsed["q"], "config": parsed,
    }


def identity_key(f: dict[str, Any]) -> tuple[Any, ...]:
    if f.get("config"):
        return C.config_key(f["config"])
    return (f.get("scheme"), f.get("host"), f.get("port"), f.get("uuid"), f.get("sni"), f.get("type"), f.get("security"))


def build_profile(lines: list[str], resolver=C.resolve):
    """Build a reference profile and resolve domain-based working servers to network prefixes.

    A large share of manually supplied working links use hostnames rather than IP literals.
    Resolving those hostnames lets the subnet signal work for them too. Only globally routable
    answers are accepted, matching the safety checks used for collected candidates.
    """
    keys = ("pbk", "sid", "uuid", "host", "fam", "sni", "subnet", "port", "type", "flow", "fp")
    profile = {key: collections.Counter() for key in keys}
    counts = collections.Counter()
    known = set()
    parsed = []
    for line in lines:
        f = features(line)
        if not f or not f.get("host"):
            continue
        parsed.append(f)

    domain_hosts = sorted({f["host"] for f in parsed if not is_ip(f["host"]) and C.public_host(f["host"])})
    resolved = {}
    if domain_hosts:
        with cf.ThreadPoolExecutor(max_workers=min(C.DNS_WORKERS, len(domain_hosts))) as executor:
            resolved = dict(zip(domain_hosts, executor.map(resolver, domain_hosts)))

    for f in parsed:
        known.add(identity_key(f))
        counts["servers"] += 1
        counts[f["scheme"]] += 1
        profile["host"][f["host"]] += 1
        for family in {reg_domain(f["host"]), reg_domain(f["sni"])} - {""}:
            profile["fam"][family] += 1
        for key in ("pbk", "sid", "uuid", "sni"):
            if f.get(key):
                profile[key][f[key]] += 1
        address = f["host"] if is_ip(f["host"]) else resolved.get(f["host"], "")
        if address:
            block = subnet24(address)
            if block:
                profile["subnet"][block] += 1
        if f["scheme"] == "vless":
            counts["vless_" + (f.get("security") or "none")] += 1
            profile["port"][int(f.get("port") or 0)] += 1
            profile["type"][f.get("type", "tcp")] += 1
            profile["flow"][f.get("flow", "")] += 1
            profile["fp"][f.get("fp", "")] += 1
    counts["working_hosts_resolved"] = sum(bool(resolved.get(host)) for host in domain_hosts)
    counts["working_hosts_dns_total"] = len(domain_hosts)
    return profile, counts, known


def pool_counters(candidates: list[dict[str, Any]]):
    keys = ("pbk", "sid", "uuid", "host", "fam", "sni", "subnet")
    counters = {key: collections.Counter() for key in keys}
    for c in candidates:
        for key in ("pbk", "sid", "uuid", "host", "sni"):
            if c.get(key):
                counters[key][c[key]] += 1
        for family in c.get("families", []):
            counters["fam"][family] += 1
        if c.get("subnet"):
            counters["subnet"][c["subnet"]] += 1
    return counters


def score(candidate: dict[str, Any], profile, pool_count, n_vless: int):
    strong, reasons = 0.0, []

    def add(key: str, value: Any, weight: float) -> float:
        if not value:
            return 0.0
        work_n = profile[key].get(value, 0)
        if not work_n:
            return 0.0
        value_score = weight * (1 + 0.12 * min(work_n - 1, 6))
        pool_n = pool_count[key].get(value, 1)
        if pool_n > COMMON_THRESHOLD:
            value_score *= COMMON_THRESHOLD / pool_n
        if value_score >= 2:
            reasons.append((key, str(value), round(value_score, 1)))
        return value_score

    strong += add("pbk", candidate.get("pbk"), WEIGHTS["pbk"])
    strong += add("sid", candidate.get("sid"), WEIGHTS["sid"])
    strong += add("uuid", candidate.get("uuid"), WEIGHTS["uuid"])
    strong += add("host", candidate.get("host"), WEIGHTS["host"])
    strong += max((add("fam", family, WEIGHTS["fam"]) for family in candidate.get("families", [])), default=0.0)
    strong += add("subnet", candidate.get("subnet"), WEIGHTS["subnet"])
    strong += add("sni", candidate.get("sni"), WEIGHTS["sni"])
    if n_vless:
        q = candidate.get("q", {})
        soft = (
            6 * profile["port"].get(candidate.get("port"), 0)
            + 4 * profile["type"].get(candidate.get("type"), 0)
            + 3 * profile["flow"].get(q.get("flow", ""), 0)
            + 2 * profile["fp"].get(q.get("fp", ""), 0)
        ) / n_vless
    else:
        soft = 0.0
    return strong, soft, reasons


def _load_pool(pool_path: Path, working_path: Path, stats: collections.Counter):
    if not pool_path.exists():
        raise FileNotFoundError(f"Не найден пул {pool_path}. Сначала запусти collector.py.")
    if not working_path.exists():
        raise FileNotFoundError(f"Не найден {working_path}. Добавь туда рабочие конфигурации.")
    pool_lines = [line.strip() for line in pool_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    working_lines = [line.strip() for line in working_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    stats["pool_lines"] = len(pool_lines)
    stats["working_lines"] = len(working_lines)
    return pool_lines, working_lines


def _deduplicate_pool(pool_lines: list[str], known: set[tuple[Any, ...]], stats):
    result: dict[tuple[Any, ...], dict[str, Any]] = {}
    for line in pool_lines:
        f = features(line)
        if not f or f.get("scheme") != "vless" or f.get("security") not in {"reality", "tls"}:
            stats["pool_unsupported"] += 1
            continue
        c = f["config"]
        if not C.public_host(c["host"]):
            stats["pool_bad_host"] += 1
            continue
        if identity_key(f) in known:
            stats["pool_exactly_in_working"] += 1
            continue
        c["families"] = sorted({reg_domain(c["host"]), reg_domain(c["sni"])} - {""})
        c["ip"] = c["host"] if is_ip(c["host"]) else ""
        c["subnet"] = subnet24(c["ip"]) if c["ip"] else ""
        key = C.config_key(c)
        result.setdefault(key, c)
    stats["pool_unique_candidates"] = len(result)
    return list(result.values())


def _checkpoint_core(out: Path, core: str, successes, candidate_by_key, completed: int) -> None:
    directory = out / "checkpoints"
    directory.mkdir(parents=True, exist_ok=True)
    links = [candidate_by_key[key]["base"] for key in successes if key in candidate_by_key]
    C.atomic_write(directory / f"{core}_passed_checkpoint.txt", "\n".join(links) + ("\n" if links else ""))
    C.atomic_write(directory / f"{core}_progress.json", json.dumps({
        "core": core, "completed": completed, "passed": len(successes),
    }, ensure_ascii=False, indent=2) + "\n")


def _core_checks(candidates: list[dict[str, Any]], xray: str | None, singbox: str | None, stats, out: Path):
    xr: dict[tuple[Any, ...], dict[str, Any]] = {}
    sb: dict[tuple[Any, ...], dict[str, Any]] = {}
    if xray:
        eligible = [c for c in candidates if C._core_config(c, 1, "xray") is not None]
        stats["xray_skipped_unsupported_transport"] = len(candidates) - len(eligible)
        batch = eligible[:MAX_PROBE]
        log(f"Xray: проверка до {len(batch)} похожих кандидатов")
        candidate_by_key = {C.config_key(c): c for c in batch}
        with cf.ThreadPoolExecutor(max_workers=CORE_WORKERS) as executor:
            futures = {executor.submit(C.probe_core, c, xray, "xray", i < C.MAX_SPEED_TEST): c
                       for i, c in enumerate(batch)}
            completed = 0
            for future in cf.as_completed(futures):
                c = futures[future]
                completed += 1
                try:
                    result = future.result()
                    if result:
                        xr[C.config_key(c)] = result
                except Exception:
                    stats["xray_errors"] += 1
                if completed % 25 == 0 or completed == len(futures):
                    _checkpoint_core(out, "xray", xr, candidate_by_key, completed)
        stats["xray_ok"] = len(xr)
    else:
        stats["xray_skipped"] = len(candidates)
    if singbox:
        eligible = [c for c in candidates if C._core_config(c, 1, "singbox") is not None]
        stats["singbox_skipped_unsupported_transport"] = len(candidates) - len(eligible)
        batch = eligible[:MAX_PROBE]
        log(f"sing-box: проверка до {len(batch)} похожих кандидатов")
        candidate_by_key = {C.config_key(c): c for c in batch}
        speed_with_singbox = not bool(xray)
        with cf.ThreadPoolExecutor(max_workers=CORE_WORKERS) as executor:
            futures = {executor.submit(C.probe_core, c, singbox, "singbox", speed_with_singbox and i < C.MAX_SPEED_TEST): c
                       for i, c in enumerate(batch)}
            completed = 0
            for future in cf.as_completed(futures):
                c = futures[future]
                completed += 1
                try:
                    result = future.result()
                    if result:
                        sb[C.config_key(c)] = result
                except Exception:
                    stats["singbox_errors"] += 1
                if completed % 25 == 0 or completed == len(futures):
                    _checkpoint_core(out, "singbox", sb, candidate_by_key, completed)
        stats["singbox_ok"] = len(sb)
    else:
        stats["singbox_skipped"] = len(candidates)
    stats["speed_probe_limit_per_core"] = C.MAX_SPEED_TEST
    return xr, sb


def _apply_final_caps(items: list[dict[str, Any]], geo: dict[str, dict[str, Any]], stats):
    # Limit per IP, Reality key, and domain family/subnet after priority sorting.
    selected: list[dict[str, Any]] = []
    per_ip, per_pbk, per_group = collections.Counter(), collections.Counter(), collections.Counter()
    ordered = sorted(items, key=lambda c: c["rank_key"])
    for c in ordered:
        # Apply family limits to both the server host family and SNI family, and
        # independently to the resolved network prefix (/24 IPv4 or /64 IPv6).
        groups = set(c.get("families", []))
        if c.get("subnet"):
            groups.add(c["subnet"])
        if not groups and c.get("ip"):
            groups.add(c["ip"])
        if per_ip[c.get("ip", "")] >= MAX_PER_IP:
            stats["dropped_per_ip"] += 1
            continue
        if c.get("pbk") and per_pbk[c["pbk"]] >= MAX_PER_PBK:
            stats["dropped_per_pbk"] += 1
            continue
        if any(per_group[group] >= MAX_PER_FAMILY for group in groups):
            stats["dropped_per_family"] += 1
            continue
        per_ip[c.get("ip", "")] += 1
        if c.get("pbk"):
            per_pbk[c["pbk"]] += 1
        for group in groups:
            per_group[group] += 1
        selected.append(c)
    return C._apply_na_cap(selected, MAX_TOTAL, geo)


def _write_outputs(out: Path, final: list[dict[str, Any]], stats, geo):
    lists_dir, reports_dir, checkpoints_dir = out / "lists", out / "reports", out / "checkpoints"
    for directory in (lists_dir, reports_dir, checkpoints_dir):
        directory.mkdir(parents=True, exist_ok=True)
    def lines(items):
        return "\n".join(f"{c['base']}#{up.quote(c.get('name', 'Unknown'))}" for c in items) + ("\n" if items else "")
    files = {
        "similar_to_working.txt": final,
        "xray_verified.txt": [c for c in final if c.get("xray_ok")],
        "singbox_verified.txt": [c for c in final if c.get("singbox_ok")],
        "verified_by_both.txt": [c for c in final if c.get("xray_ok") and c.get("singbox_ok")],
        "similar_verified.txt": [c for c in final if c.get("verified")],
    }
    for filename, data in files.items():
        C.atomic_write(lists_dir / filename, lines(data))
    C.atomic_write(lists_dir / "similar_to_working_b64.txt", base64.b64encode(lines(final).encode()).decode() + "\n")
    dist = collections.Counter(C._country_code(c, geo) or "UNKNOWN" for c in final)
    stats["final_country_distribution"] = dict(sorted(dist.items()))
    stats["final_us_ca_share"] = round(sum(dist[x] for x in ("US", "CA")) / len(final), 4) if final else 0
    stats["final_us_ca_plus_unknown_share"] = round(
        (sum(dist[x] for x in ("US", "CA")) + dist.get("UNKNOWN", 0)) / len(final), 4
    ) if final else 0
    stats["final_unknown_geo"] = dist.get("UNKNOWN", 0)
    stats["north_america_quota_includes_unknown_geo"] = True
    stats["final_count"] = len(final)
    C.atomic_write(reports_dir / "report.json", json.dumps(dict(stats), ensure_ascii=False, indent=2, default=str) + "\n")
    report = ["SIMILAR-TO-WORKING REPORT", "", f"Final: {len(final)}", "", "Statistics:"]
    report.extend(f"{key}: {value}" for key, value in sorted(stats.items()))
    report.extend(["", "Top matches:"])
    for c in final[:40]:
        why = ", ".join(f"{key}={value[:28]}(+{points})" for key, value, points in c.get("why", [])[:4])
        cores = ",".join(core for core in ("Xray" if c.get("xray_ok") else "", "sing-box" if c.get("singbox_ok") else "") if core)
        report.append(f"{c.get('rank', 0):.1f} [{cores or 'TCP only'}] {c.get('name', '')} — {why}")
    C.atomic_write(reports_dir / "similar_report.txt", "\n".join(report) + "\n")
    summary = {
        "working_servers": dict(stats.get("working_profile_counts", {})),
        "pbk_groups": [[value[:10] + "…", count] for value, count in stats.get("profile_pbk", [])],
        "domain_families": stats.get("profile_families", []),
        "sni": stats.get("profile_sni", []),
        "ports": stats.get("profile_ports", []),
        "transports": stats.get("profile_transports", []),
    }
    C.atomic_write(reports_dir / "working_profile.json", json.dumps(summary, ensure_ascii=False, indent=2) + "\n")


def run(args: argparse.Namespace) -> int:
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    stats: collections.Counter = collections.Counter()
    pool_lines, working_lines = _load_pool(Path(args.pool), Path(args.working), stats)
    profile, counts, known = build_profile(working_lines)
    stats["working_profile_counts"] = dict(counts)
    stats["profile_pbk"] = profile["pbk"].most_common(12)
    stats["profile_families"] = profile["fam"].most_common(15)
    stats["profile_sni"] = profile["sni"].most_common(15)
    stats["profile_ports"] = profile["port"].most_common(10)
    stats["profile_transports"] = profile["type"].most_common(10)
    n_vless = counts["vless"]
    stats["working_valid"] = counts["servers"]
    if counts["servers"] < 1:
        raise ValueError("my_working.txt не содержит распознаваемых VLESS/VMess конфигураций. Проверь формат и вставь полные ссылки по одной на строку.")
    log(f"Пул: {len(pool_lines)}; рабочих валидных записей: {counts['servers']}")
    candidates = _deduplicate_pool(pool_lines, known, stats)
    pool_count = pool_counters(candidates)
    for c in candidates:
        c["strong"], c["soft"], c["why"] = score(c, profile, pool_count, n_vless)
        c["pre_rank"] = c["strong"] + c["soft"]
    similar = [c for c in candidates if c["strong"] >= args.min_score]
    stats["matched_before_dns"] = len(similar)
    # Resolve hosts in descending score order; do not let source order consume the DNS budget.
    similar.sort(key=lambda c: (-c["pre_rank"], -c["strong"], c["base"]))
    dns_targets = [c for c in similar if not c.get("ip")]
    host_order = list(dict.fromkeys(c["host"] for c in dns_targets))[:MAX_DNS]
    stats["dns_hosts_queued"] = len(host_order)
    with cf.ThreadPoolExecutor(max_workers=C.DNS_WORKERS) as executor:
        resolved = dict(zip(host_order, executor.map(C.resolve, host_order)))
    pool: list[dict[str, Any]] = []
    for c in similar:
        item = dict(c)
        if not item.get("ip"):
            item["ip"] = resolved.get(item["host"], "")
        if not item.get("ip"):
            stats["dns_failed_or_over_limit"] += 1
            continue
        if not ipaddress.ip_address(item["ip"]).is_global:
            stats["dns_non_global"] += 1
            continue
        item["subnet"] = subnet24(item["ip"])
        pool.append(item)
    stats["dns_ok"] = len(pool)
    pool_count = pool_counters(pool)
    for c in pool:
        c["strong"], c["soft"], c["why"] = score(c, profile, pool_count, n_vless)
        c["pre_rank"] = c["strong"] + c["soft"]
    pool.sort(key=lambda c: (-c["pre_rank"], -c["strong"], c["base"]))
    stats["similar_after_dns"] = len(pool)
    batch = pool[:MAX_TCP]
    stats["tcp_batch"] = len(batch)
    stats["skipped_after_tcp_limit"] = max(0, len(pool) - len(batch))
    log(f"Похожих после DNS: {len(pool)}; TCP проверка: {len(batch)}")
    with cf.ThreadPoolExecutor(max_workers=C.TCP_WORKERS) as executor:
        ping_values = list(executor.map(C.tcp_ping, batch))
    # Retry TCP misses once with a longer timeout to reduce false negatives from packet loss.
    retry_indices = [index for index, value in enumerate(ping_values) if value is None]
    if retry_indices:
        with cf.ThreadPoolExecutor(max_workers=C.TCP_WORKERS) as executor:
            retry_values = list(executor.map(lambda index: C.tcp_ping(batch[index], C.TCP_RETRY_TIMEOUT), retry_indices))
        recovered = 0
        for index, value in zip(retry_indices, retry_values):
            ping_values[index] = value
            recovered += value is not None
        stats["tcp_recovered_on_retry"] = recovered
    alive = [dict(c, ms=round(float(ms), 2)) for c, ms in zip(batch, ping_values) if ms is not None]
    stats["tcp_ok"] = len(alive)
    stats["tcp_failed"] = len(batch) - len(alive)
    checkpoints_dir = out / "checkpoints"
    checkpoints_dir.mkdir(parents=True, exist_ok=True)
    C.atomic_write(checkpoints_dir / "tcp_alive_checkpoint.txt", "\n".join(c["base"] for c in alive[:MAX_TOTAL * 3]) + ("\n" if alive else ""))
    alive.sort(key=lambda c: (-c["pre_rank"], -c["strong"], c["ms"], c["base"]))

    xray = shutil.which(args.xray or os.environ.get("XRAY_BIN") or "xray") if not args.no_xray else None
    singbox = shutil.which(args.sing_box or os.environ.get("SING_BOX_BIN") or "sing-box") if not args.no_singbox else None
    if not shutil.which("curl"):
        xray = singbox = None
        stats["curl_missing"] = 1
    stats["xray_available"] = bool(xray)
    stats["singbox_available"] = bool(singbox)
    xray_results, singbox_results = _core_checks(alive, xray, singbox, stats, out)
    tested: list[dict[str, Any]] = []
    for c in alive:
        key = C.config_key(c)
        xr, sb = xray_results.get(key), singbox_results.get(key)
        item = dict(c)
        item["xray_ok"] = bool(xr)
        item["singbox_ok"] = bool(sb)
        if xr:
            item.update({"exit_ip": xr["exit_ip"], "exit_cc": xr["exit_cc"], "xray_mbps": xr["mbps"]})
        if sb:
            item.update({"singbox_exit_ip": sb["exit_ip"], "singbox_exit_cc": sb["exit_cc"], "singbox_mbps": sb["mbps"]})
            if not xr:
                item.update({"exit_ip": sb["exit_ip"], "exit_cc": sb["exit_cc"]})
        item["mbps"] = max((v for v in ((xr or {}).get("mbps", 0), (sb or {}).get("mbps", 0)) if v), default=0.0)
        item["verified"] = bool(xr or sb)
        # Similarity is dominant; core pass and throughput break ties rather than masking similarity.
        item["rank"] = item["strong"] + item["soft"] + (VERIFIED_BONUS if item["verified"] else 0)
        item["rank_key"] = (-item["rank"], -item["strong"], -item["mbps"], item["ms"], item["base"])
        tested.append(item)
    ips = {c["ip"] for c in tested}
    ips |= {c["exit_ip"] for c in tested if c.get("exit_ip")}
    geo = C.geo_lookup(ips, args.mmdb)
    for c in tested:
        c["name"] = C.make_name(geo.get(c.get("exit_ip") or c["ip"]), c.get("exit_cc", ""))
    final, na_dropped = _apply_final_caps(tested, geo, stats)
    stats["north_america_dropped_by_25pct_cap"] = na_dropped
    stats["verified"] = sum(c["verified"] for c in final)
    stats["xray_verified"] = sum(c["xray_ok"] for c in final)
    stats["singbox_verified"] = sum(c["singbox_ok"] for c in final)
    stats["verified_by_both"] = sum(c["xray_ok"] and c["singbox_ok"] for c in final)
    _write_outputs(out, final, stats, geo)
    log(f"Готово: results/similar — {len(final)} записей; ядра: Xray {stats.get('xray_ok', 0)}, sing-box {stats.get('singbox_ok', 0)}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Поиск конфигураций, похожих на my_working.txt")
    parser.add_argument("--pool", default=str(DEFAULT_POOL))
    parser.add_argument("--working", default=str(DEFAULT_WORKING))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--xray", default=None)
    parser.add_argument("--sing-box", dest="sing_box", default=None)
    parser.add_argument("--mmdb", default=None)
    parser.add_argument("--min-score", type=float, default=MIN_SCORE)
    parser.add_argument("--no-xray", action="store_true")
    parser.add_argument("--no-singbox", action="store_true")
    args = parser.parse_args()
    try:
        raise SystemExit(run(args))
    except (FileNotFoundError, OSError, ValueError) as exc:
        log(f"ОШИБКА: {exc}")
        raise SystemExit(2)
    except KeyboardInterrupt:
        log("Остановлено пользователем.")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
