#!/usr/bin/env python3
"""Дополнительная обработка источников igareck без TCP/Xray/sing-box проверок.

Создаёт results/black_list.txt и results/white_cidr.txt: строго одна
конфигурация на каждый endpoint IP, без повторов IP внутри файла.
В all.txt/working_proxies.txt добавляет строго одну конфигурацию на IP.

Для дедупликации доменных адресов выполняется только DNS-разрешение; TCP-соединения
и проверки через Xray/sing-box не запускаются.
"""
from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

import checker as base

BLACK_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Export/Base64/PROXIES_ONLY/BLACK_SS%2BAll_RUS_base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Export/Base64/PROXIES_ONLY/BLACK_VLESS_RUS_base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Export/Base64/PROXIES_ONLY/BLACK_VLESS_RUS_mobile_base64.txt",
]
WHITE_CIDR_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Export/Base64/PROXIES_ONLY/WHITE-SNI-RU-all-base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Export/Base64/PROXIES_ONLY/WHITE-CIDR-RU-all-base64.txt",
]
MAX_CONFIGS_PER_IP = int(__import__("os").getenv("IGARECK_MAX_CONFIGS_PER_IP", "1"))
DNS_CONCURRENCY = int(__import__("os").getenv("IGARECK_DNS_CONCURRENCY", "40"))


def read_lines(path: Path) -> list[str]:
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except FileNotFoundError:
        return []


async def download_group(name: str, urls: list[str]) -> tuple[list[str], int, int]:
    """Скачивает каждую подписку отдельно, декодирует Base64 и считает реально распознанные ссылки."""
    lines: list[str] = []
    succeeded = 0
    failed = 0
    seen_lines: set[str] = set()
    for index, url in enumerate(urls, 1):
        try:
            text = await asyncio.to_thread(base.fetch_url, url)
            decoded = base.maybe_decode_subscription(text)
            parsed_here = 0
            raw_count = 0
            for raw_line in decoded.splitlines():
                raw_count += 1
                line = base.parse_line(raw_line)
                if line:
                    parsed_here += 1
                    if line not in seen_lines:
                        seen_lines.add(line)
                        lines.append(line)
            if parsed_here == 0:
                failed += 1
                print(
                    f"igareck/{name} [{index}/{len(urls)}]: источник загружен, "
                    f"но подходящих конфигураций не распознано "
                    f"(строк после декодирования: {raw_count}, размер: {len(text)} символов): {url}"
                )
                continue
            succeeded += 1
            print(
                f"igareck/{name} [{index}/{len(urls)}]: распознано {parsed_here} "
                f"конфигураций (уникальных новых: {len(lines)} суммарно)"
            )
        except Exception as exc:
            failed += 1
            print(f"igareck/{name}: ошибка источника {url}: {exc}")
    print(
        f"igareck/{name}: источников с конфигурациями {succeeded}/{len(urls)}, "
        f"неудачных {failed}, уникальных конфигураций {len(lines)}"
    )
    return lines, succeeded, failed


async def resolve_candidates(lines: list[str]) -> list[tuple[str, str]]:
    """Возвращает (конфигурация, endpoint IP); никаких TCP-подключений нет."""
    hosts: dict[str, str | None] = {}
    for line in lines:
        host, port = base.extract_host_port(line)
        if host and isinstance(port, int) and 1 <= port <= 65535 and host not in hosts:
            hosts[host] = None

    sem = asyncio.Semaphore(DNS_CONCURRENCY)

    async def resolve(host: str) -> tuple[str, str | None]:
        async with sem:
            try:
                return host, await base.resolve_public_ip(host)
            except Exception:
                return host, None

    if hosts:
        resolved = await asyncio.gather(*(resolve(host) for host in hosts))
        hosts.update(dict(resolved))

    result: list[tuple[str, str]] = []
    unresolved = 0
    for line in lines:
        host, _ = base.extract_host_port(line)
        ip = hosts.get(host or "")
        if ip:
            result.append((line, ip))
        else:
            unresolved += 1
    print(f"DNS: адресов {len(hosts)}, конфигураций с публичным IP {len(result)}, без разрешения {unresolved}")
    return result


def limit_per_ip(items: list[tuple[str, str]], max_configs_per_ip: int) -> list[tuple[str, str]]:
    """Оставляет до N разных конфигураций НА КАЖДЫЙ IP; число IP не ограничивает."""
    counts: dict[str, int] = {}
    seen_lines: set[str] = set()
    result: list[tuple[str, str]] = []
    for line, ip in items:
        if not ip or line in seen_lines:
            continue
        count = counts.get(ip, 0)
        if count >= max_configs_per_ip:
            continue
        seen_lines.add(line)
        counts[ip] = count + 1
        result.append((line, ip))
    return result


def load_metrics(path: Path, lines: list[str]) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list) and len(data) == len(lines) and all(isinstance(row, dict) for row in data):
            return data
    except Exception:
        pass
    return []


async def metrics_for_existing(lines: list[str], metrics_path: Path) -> list[dict]:
    metrics = load_metrics(metrics_path, lines)
    if metrics:
        return metrics
    pairs = await resolve_candidates(lines)
    ip_by_line = {line: ip for line, ip in pairs}
    result = []
    for line in lines:
        result.append({
            "scheme": base.get_scheme(line), "country": "XX", "city": "",
            "ip": ip_by_line.get(line, ""), "latency_ms": None, "speed_mbps": None,
        })
    return result


async def main() -> int:
    if MAX_CONFIGS_PER_IP < 1 or DNS_CONCURRENCY < 1:
        raise ValueError("IGARECK_MAX_CONFIGS_PER_IP и IGARECK_DNS_CONCURRENCY должны быть >= 1")

    base._source_bytes_used = 0
    black_raw, black_ok, _ = await download_group("black_list", BLACK_SOURCES)
    white_raw, white_ok, _ = await download_group("white_cidr", WHITE_CIDR_SOURCES)
    if black_ok + white_ok == 0:
        print("Все источники igareck недоступны; существующие результаты не изменены")
        return 1

    # Разрешаем группы раздельно: если у одного из источников домен не резолвится,
    # это не должно сдвигать границу между black и white списками.
    black_resolved = await resolve_candidates(black_raw)
    white_resolved = await resolve_candidates(white_raw)
    black_items = limit_per_ip(black_resolved, MAX_CONFIGS_PER_IP)
    white_items = limit_per_ip(white_resolved, MAX_CONFIGS_PER_IP)

    out_dir: Path = base.OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    if black_ok:
        base.atomic_write_text(out_dir / "black_list.txt", "\n".join(line for line, _ in black_items) + ("\n" if black_items else ""))
    if white_ok:
        base.atomic_write_text(out_dir / "white_cidr.txt", "\n".join(line for line, _ in white_items) + ("\n" if white_items else ""))

    # В общий файл — одна конфигурация на каждый новый endpoint IP (без повторов
    # между black/white группами и без повторов с уже проверенным основным списком).
    main_path = out_dir / "all.txt"
    mirror_path = out_dir / "working_proxies.txt"
    metrics_path = out_dir / "metrics.json"
    main_lines = read_lines(main_path)
    metrics = await metrics_for_existing(main_lines, metrics_path)
    existing_ips = {str(row.get("ip", "")) for row in metrics if row.get("ip")}

    additions: list[tuple[str, str]] = []
    addition_ips: set[str] = set()
    for line, ip in black_items + white_items:
        if ip in existing_ips or ip in addition_ips:
            continue
        addition_ips.add(ip)
        additions.append((line, ip))

    # Сохраняем ограничение MAX_TOTAL общего списка: при необходимости освобождаем
    # места из конца основного (отсортированного) списка под дополнительные записи.
    max_total = max(1, base.MAX_TOTAL)
    # Общий файл ограничен MAX_TOTAL. Если уникальных IP из igareck больше этого
    # лимита, берём первые max_total, иначе освобождаем только необходимое место.
    if len(additions) > max_total:
        print(
            f"all.txt: уникальных IP igareck ({len(additions)}) больше лимита "
            f"MAX_TOTAL={max_total}; в общий файл войдут первые {max_total}"
        )
        additions = additions[:max_total]
    if len(main_lines) + len(additions) > max_total:
        keep_n = max(0, max_total - len(additions))
        removed = len(main_lines) - keep_n
        main_lines = main_lines[:keep_n]
        metrics = metrics[:keep_n]
        print(f"all.txt: освобождено {removed} мест под дополнительные записи igareck")

    for line, ip in additions:
        main_lines.append(line)
        metrics.append({
            "scheme": base.get_scheme(line), "country": "XX", "city": "",
            "ip": ip, "latency_ms": None, "speed_mbps": None,
            "source": "igareck", "checked": False,
        })

    payload = "\n".join(main_lines) + ("\n" if main_lines else "")
    base.atomic_write_text(main_path, payload)
    base.atomic_write_text(mirror_path, payload)
    base.atomic_write_text(metrics_path, json.dumps(metrics, ensure_ascii=False, separators=(",", ":")))

    stats_path = out_dir / "stats.json"
    try:
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
        if not isinstance(stats, dict):
            stats = {}
    except Exception:
        stats = {}
    files = stats.setdefault("files", {})
    if not isinstance(files, dict):
        files = stats["files"] = {}
    files["all_txt"] = len(main_lines)
    files["igareck_black_list"] = len(black_items)
    files["igareck_white_cidr"] = len(white_items)
    stats["all_txt_by_protocol"] = dict(Counter(base.get_scheme(line) for line in main_lines))
    # Страновые доли нельзя достоверно пересчитать без туннельной проверки igareck.
    stats["all_txt_us_ca"] = None
    stats["all_txt_us_ca_share"] = None
    stats["all_txt_europe_share"] = None
    share_info = files.setdefault("us_ca_share", {})
    if isinstance(share_info, dict):
        share_info["all_txt"] = None
    stats["igareck"] = {
        "tcp_checked": False,
        "xray_checked": False,
        "singbox_checked": False,
        "dns_resolution_only": True,
        "max_configs_per_ip": MAX_CONFIGS_PER_IP,
        "black_list_unique_ips": len({ip for _, ip in black_items}),
        "white_cidr_unique_ips": len({ip for _, ip in white_items}),
        "black_list_configs": len(black_items),
        "white_cidr_configs": len(white_items),
        "added_to_all_txt": len(additions),
    }
    base.atomic_write_text(stats_path, json.dumps(stats, ensure_ascii=False, indent=2))

    print(
        "igareck готов: "
        f"black_list={len(black_items)} конфигов / {len({ip for _, ip in black_items})} IP "
        f"(ровно не более {MAX_CONFIGS_PER_IP} на IP); "
        f"white_cidr={len(white_items)} конфигов / {len({ip for _, ip in white_items})} IP "
        f"(ровно не более {MAX_CONFIGS_PER_IP} на IP); "
        f"добавлено в all.txt={len(additions)}; итог all.txt={len(main_lines)}"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:
        print(f"Критическая ошибка igareck.py: {exc}", file=sys.stderr)
        sys.exit(1)
