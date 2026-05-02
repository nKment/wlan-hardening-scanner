#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml


def load_yaml(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_command(cmd: list[str], timeout: int = 30) -> dict[str, Any]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "ok": result.returncode == 0,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": " ".join(cmd),
            "returncode": None,
            "stdout": (exc.stdout or "").strip() if exc.stdout else "",
            "stderr": "Command timed out",
            "ok": False,
        }
    except Exception as exc:
        return {
            "command": " ".join(cmd),
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "ok": False,
        }


def parse_key_value_block(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()
    return data


def get_wifi_info() -> dict[str, Any]:
    raw = run_command(["networksetup", "-getinfo", "Wi-Fi"])
    parsed = parse_key_value_block(raw["stdout"])

    ip_addr = parsed.get("IP address")
    router = parsed.get("Router")
    subnet_mask = parsed.get("Subnet mask")

    return {
        "raw": raw,
        "ip_address": None if ip_addr in (None, "none") else ip_addr,
        "router": None if router in (None, "none") else router,
        "subnet_mask": None if subnet_mask in (None, "none") else subnet_mask,
    }


def ip_in_subnet(ip_addr: str | None, subnet_cidr: str) -> bool:
    if not ip_addr:
        return False
    return ipaddress.ip_address(ip_addr) in ipaddress.ip_network(subnet_cidr, strict=False)


def ping_host(host: str, count: int = 4) -> dict[str, Any]:
    raw = run_command(["ping", "-c", str(count), host], timeout=20)
    stdout = raw["stdout"]

    packet_loss = None
    avg_ms = None

    loss_match = re.search(r"([0-9.]+)% packet loss", stdout)
    if loss_match:
        packet_loss = float(loss_match.group(1))

    rtt_match = re.search(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms", stdout)
    if rtt_match:
        avg_ms = float(rtt_match.group(2))

    success = packet_loss is not None and packet_loss < 100.0

    return {
        "host": host,
        "success": success,
        "packet_loss_percent": packet_loss,
        "avg_ms": avg_ms,
        "raw": raw,
    }


def scan_ports(host: str, ports: list[int]) -> dict[str, Any]:
    port_str = ",".join(str(p) for p in ports)
    raw = run_command(["nmap", "-Pn", "-p", port_str, host], timeout=45)

    states: dict[int, str] = {}
    for line in raw["stdout"].splitlines():
        m = re.match(r"^(\d+)/tcp\s+(\S+)\s+", line.strip())
        if m:
            port = int(m.group(1))
            state = m.group(2)
            states[port] = state

    return {
        "host": host,
        "ports": ports,
        "states": states,
        "raw": raw,
    }


def arp_entries() -> dict[str, Any]:
    raw = run_command(["arp", "-a"], timeout=10)
    ips = re.findall(r"\((\d+\.\d+\.\d+\.\d+)\)", raw["stdout"])
    return {
        "count": len(ips),
        "ips": ips,
        "raw": raw,
    }


def discover_hosts(subnet: str) -> dict[str, Any]:
    raw = run_command(["nmap", "-sn", "-n", subnet], timeout=60)
    stdout = raw["stdout"]

    hosts = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", stdout)

    hosts_up_match = re.search(r"\((\d+) hosts? up\)", stdout)
    if hosts_up_match:
        hosts_up = int(hosts_up_match.group(1))
    else:
        hosts_up = len(hosts)

    return {
        "subnet": subnet,
        "hosts_up": hosts_up,
        "hosts": hosts,
        "raw": raw,
    }


def build_results(profile_name: str, profile_cfg: dict[str, Any]) -> dict[str, Any]:
    results: dict[str, Any] = {}

    wifi = get_wifi_info()
    results["wifi"] = wifi

    results["ip_in_expected_subnet"] = ip_in_subnet(
        wifi["ip_address"],
        profile_cfg["expected_subnet"]
    )
    results["gateway_matches_expected"] = wifi["router"] == profile_cfg["expected_gateway"]

    results["gateway_ping"] = ping_host(profile_cfg["expected_gateway"], count=4)
    results["external_ping"] = ping_host(profile_cfg["external_test_ip"], count=4)

    mgmt_gateway = profile_cfg.get("management_gateway")
    results["management_gateway_ping"] = ping_host(mgmt_gateway, count=4) if mgmt_gateway else None

    results["management_hosts"] = []
    for host in profile_cfg.get("management_hosts", []):
        results["management_hosts"].append({
            "host": host,
            "ping": ping_host(host, count=4),
            "ports": scan_ports(host, [80, 443]),
        })

    results["arp"] = arp_entries()
    results["discovery"] = discover_hosts(profile_cfg["discovery_subnet"])
    results["profile"] = profile_name

    return results


def score_authentication(observed: dict[str, Any]) -> int:
    mode = str(observed.get("auth_mode", "")).lower()

    if mode in {"", "open", "wep"}:
        return 0
    if mode in {"wpa2", "wpa2_psk", "wpa2-psk"}:
        return 1
    if mode in {"wpa3_transition", "wpa3_wpa2_transition", "wpa3_personal_wpa2_psk"}:
        return 2
    if mode in {"wpa3", "wpa3_only", "wpa3_sae"}:
        return 3
    return 0


def score_management(results: dict[str, Any]) -> int:
    mgmt_hosts = results.get("management_hosts", [])
    mgmt_gateway_ping = results.get("management_gateway_ping")

    any_open = False
    all_ping_fail = True
    all_filtered_or_closed = True

    for item in mgmt_hosts:
        if item["ping"]["success"]:
            all_ping_fail = False

        for _, state in item["ports"]["states"].items():
            if state == "open":
                any_open = True
                all_filtered_or_closed = False
            elif state not in {"filtered", "closed"}:
                all_filtered_or_closed = False

    if any_open:
        return 0

    if all_filtered_or_closed and all_ping_fail:
        if mgmt_gateway_ping and mgmt_gateway_ping.get("success"):
            return 2
        return 3

    return 1


def score_segmentation(observed: dict[str, Any], results: dict[str, Any]) -> int:
    vlans = set(observed.get("vlans_present", []))
    management_cfg = bool(observed.get("management_network_configured", False))
    ip_ok = results["ip_in_expected_subnet"]
    gw_ok = results["gateway_matches_expected"]

    if not vlans:
        return 0

    if {20, 30, 99}.issubset(vlans) and management_cfg and ip_ok and gw_ok:
        return 3

    if len(vlans) >= 2 and ip_ok:
        return 2

    return 1


def score_exposure(results: dict[str, Any]) -> int:
    hosts_up = results["discovery"]["hosts_up"]

    any_open = False
    for item in results.get("management_hosts", []):
        for _, state in item["ports"]["states"].items():
            if state == "open":
                any_open = True

    if any_open or hosts_up >= 3:
        return 0
    if hosts_up == 2:
        return 1
    if hosts_up == 1:
        return 2
    return 2


def score_vulnerabilities(observed: dict[str, Any]) -> int:
    return 3 if observed.get("wps_disabled", False) else 0


def compute_category_scores(observed: dict[str, Any], results: dict[str, Any]) -> dict[str, int]:
    return {
        "authentication_and_encryption": score_authentication(observed),
        "management_access_control": score_management(results),
        "network_segmentation": score_segmentation(observed, results),
        "network_exposure": score_exposure(results),
        "known_insecure_features_or_vulnerabilities": score_vulnerabilities(observed),
    }


def compute_weighted_scores(category_scores: dict[str, int], weights: dict[str, int]) -> dict[str, Any]:
    categories: dict[str, Any] = {}
    total = 0
    max_score = 0

    for category, score in category_scores.items():
        weight = weights[category]
        weighted_value = score * weight
        categories[category] = {
            "score": score,
            "weight": weight,
            "weighted_value": weighted_value,
        }
        total += weighted_value
        max_score += 3 * weight

    percentage_of_max = round((total / max_score) * 100, 1) if max_score else 0.0

    return {
        "categories": categories,
        "total": total,
        "max_score": max_score,
        "percentage_of_max": percentage_of_max,
    }


CATEGORY_LABELS = {
    "authentication_and_encryption": "Authentication and Encryption",
    "management_access_control": "Management Access Control",
    "network_segmentation": "Network Segmentation",
    "network_exposure": "Network Exposure",
    "known_insecure_features_or_vulnerabilities": "Known Insecure Features / Vulnerabilities",
}


def print_report(profile: str, results: dict[str, Any], weighted: dict[str, Any]) -> None:
    print("=" * 72)
    print(f"WLAN Hardening Assessment: {profile}")
    print("=" * 72)

    print(f"Client IP: {results['wifi']['ip_address']}")
    print(f"Gateway:   {results['wifi']['router']}")
    print(f"IP in expected subnet: {results['ip_in_expected_subnet']}")
    print(f"Gateway matches expected: {results['gateway_matches_expected']}")
    print(f"Gateway reachable: {results['gateway_ping']['success']}")
    print(f"External reachable: {results['external_ping']['success']}")
    print(f"Hosts up in discovery scan: {results['discovery']['hosts_up']}")
    print()

    print("Management hosts:")
    for item in results["management_hosts"]:
        print(f"  - {item['host']}: ping={item['ping']['success']}, ports={item['ports']['states']}")

    if results["management_gateway_ping"] is not None:
        print(f"Management gateway reachable: {results['management_gateway_ping']['success']}")
    print()

    print("Category scores:")
    for category, data in weighted["categories"].items():
        print(
            f"  - {CATEGORY_LABELS[category]}: "
            f"{data['score']}/3, weight={data['weight']}, weighted={data['weighted_value']}"
        )

    print()
    print(f"Weighted total: {weighted['total']} / {weighted['max_score']}")
    print(f"Security level: {weighted['percentage_of_max']}%")
    print("=" * 72)


def write_json_report(path: str, payload: dict[str, Any]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prototype WLAN Hardening Scanner")
    parser.add_argument(
        "--profile",
        required=True,
        choices=["baseline", "hardened_internal", "hardened_guest"],
    )
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--observed", required=True)
    parser.add_argument("--json-out", default=None)

    args = parser.parse_args()

    cfg = load_yaml(args.config)
    observed = load_yaml(args.observed)

    profile_cfg = cfg["profiles"][args.profile]
    weights = cfg["weights"]

    results = build_results(args.profile, profile_cfg)
    category_scores = compute_category_scores(observed, results)
    weighted = compute_weighted_scores(category_scores, weights)

    payload = {
        "profile": args.profile,
        "results": results,
        "observed": observed,
        "category_scores": category_scores,
        "weighted_scores": weighted,
    }

    print_report(args.profile, results, weighted)

    if args.json_out:
        write_json_report(args.json_out, payload)


if __name__ == "__main__":
    main()