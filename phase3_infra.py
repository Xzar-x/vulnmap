# /usr/local/share/vulnmap/phase3_infra.py

import json
import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List

import vulnmap_config as config
import vulnmap_utils as utils
from rich.panel import Panel

# Stałe
TESTSSL_PATH = os.path.join(config.SHARE_DIR, "testssl.sh", "testssl.sh")


def _get_template_path_infra(category: str) -> str:
    """Zwraca ścieżkę do szablonu."""
    paths_to_check = [
        os.path.join(config.NUCLEI_TEMPLATES_DIR, category),
        os.path.join(config.NUCLEI_TEMPLATES_DIR, "http", category),
        os.path.join(config.NUCLEI_TEMPLATES_DIR, "network", category),
    ]
    for p in paths_to_check:
        if os.path.exists(p):
            return p
    return category


def _parse_nmap_vuln_output(nmap_output: str) -> List[Dict[str, Any]]:
    """Parser dla Nmap --script=vuln."""
    findings = []
    host_pattern = re.compile(r"Nmap scan report for (\S+)")
    vuln_pattern = re.compile(
        r"^\s*\|\s+(\S+):(.+)\n\s*\|\s+State: VULNERABLE", re.MULTILINE
    )

    current_host = "N/A"
    host_match = host_pattern.search(nmap_output)
    if host_match:
        current_host = host_match.group(1)

    for match in vuln_pattern.finditer(nmap_output):
        script_name, title = match.groups()
        findings.append(
            {
                "vulnerability": f"Nmap: {title.strip()}",
                "severity": "high",
                "target": current_host,
                "details": f"Nmap script '{script_name}' reported a vulnerability.",
                "remediation": "Check Nmap script documentation.",
                "source": "Nmap NSE",
            }
        )
    return findings


def _run_testssl(hosts_with_ports: Dict[str, List[Dict]]) -> List[Dict[str, Any]]:
    """Uruchamia testssl.sh dla hostów z portem 443."""
    findings = []
    if not os.path.exists(TESTSSL_PATH):
        utils.log_and_echo("testssl.sh nie znaleziony (uruchom install.py).", "WARN")
        return []

    # Filtrujemy tylko hosty z HTTPS (443)
    ssl_targets = []
    for host, ports in hosts_with_ports.items():
        if any(p.get("port") == 443 for p in ports):
            ssl_targets.append(host)

    if not ssl_targets:
        return []

    utils.log_and_echo("Rozpoczynam skanowanie SSL/TLS (testssl.sh)...", "INFO")

    # Ograniczenie liczby celów
    targets_to_scan = ssl_targets[:3] if config.SAFE_MODE else ssl_targets[:5]

    for host in targets_to_scan:
        output_html = os.path.join(config.REPORT_DIR, f"testssl_{host}.html")
        output_json = os.path.join(config.REPORT_DIR, f"testssl_{host}.json")

        command = [
            TESTSSL_PATH,
            "--quiet",
            "--fast",
            "--jsonfile",
            output_json,
            "--htmlfile",
            output_html,
            host,
        ]

        try:
            # testssl.sh może długo trwać
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=600,
            )

            # Parsowanie JSON z testssl
            if os.path.exists(output_json):
                with open(output_json, "r") as f:
                    try:
                        data = json.load(f)
                        # Szukamy tylko high/critical w wynikach
                        for item in data:
                            # Uproszczona logika - testssl zwraca specyficzny format
                            severity = item.get("severity", "INFO")
                            if severity in ["HIGH", "CRITICAL"]:
                                findings.append(
                                    {
                                        "vulnerability": f"SSL: {item.get('id')}",
                                        "severity": severity.lower(),
                                        "target": host,
                                        "details": f"Finding: {item.get('finding')}\nSee full report: {output_html}",
                                        "remediation": "Update SSL configuration/libraries.",
                                        "source": "testssl.sh",
                                    }
                                )
                    except:
                        pass
        except subprocess.TimeoutExpired:
            utils.log_and_echo(f"testssl.sh timeout dla {host}", "WARN")

    return findings


def _run_nmap_vuln_scripts(host: str, ports: List[int]) -> List[Dict[str, Any]]:
    """Uruchamia Nmap z flagą --script=vuln."""
    if not ports:
        return []
    port_str = ",".join(map(str, ports))
    utils.log_and_echo(
        f"Uruchamiam Nmap NSE (vuln) dla {host} na portach: {port_str}", "INFO"
    )

    command = ["nmap", "-sV", "-Pn", "--script=vuln", "-p", port_str, host]

    try:
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=config.TOOL_TIMEOUT_SECONDS
        )
        return _parse_nmap_vuln_output(process.stdout)
    except subprocess.TimeoutExpired:
        utils.log_and_echo(f"Skanowanie Nmap NSE dla {host} timeout.", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Błąd Nmap NSE dla {host}: {e}", "ERROR")
    return []


def _run_nuclei_infra(hosts_with_ports: Dict[str, List[Dict]]) -> List[Dict[str, Any]]:
    """Uruchamia Nuclei z szablonami sieciowymi."""
    targets = [
        f"{host}:{p['port']}" for host, ports in hosts_with_ports.items() for p in ports
    ]
    if not targets:
        return []

    utils.log_and_echo(
        "Uruchamiam skanowanie infrastruktury za pomocą Nuclei...", "INFO"
    )

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp_file:
        tmp_file.write("\n".join(targets))
        targets_file = tmp_file.name

    output_file = os.path.join(config.REPORT_DIR, "nuclei_infra_results.json")

    categories = ["network", "ssl", "dns", "file"]
    templates_args = []
    for cat in categories:
        path = _get_template_path_infra(cat)
        if os.path.exists(path):
            templates_args.extend(["-t", path])

    if not templates_args:
        templates_args = ["-t", "network/", "-t", "ssl/", "-t", "dns/"]

    command = [
        "nuclei",
        "-l",
        targets_file,
        "-json",
        "-o",
        output_file,
        "-silent",
        "-rate-limit",
        str(
            config.NUCLEI_RATE_LIMIT_SAFE
            if config.SAFE_MODE
            else config.NUCLEI_RATE_LIMIT
        ),
    ] + templates_args

    try:
        subprocess.run(command, timeout=config.TOOL_TIMEOUT_SECONDS)
        from phase1_passive import _parse_nuclei_output

        findings = _parse_nuclei_output(output_file)
        utils.log_and_echo(
            f"Nuclei (infra) zakończył. Znaleziono {len(findings)} problemów.", "INFO"
        )
        return findings
    except Exception as e:
        utils.log_and_echo(f"Błąd Nuclei Infra: {e}", "ERROR")
    finally:
        if os.path.exists(targets_file):
            os.remove(targets_file)
    return []


def start_infra_scan(categorized_targets: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Punkt wejściowy dla Fazy 3."""
    utils.console.print(
        Panel("[bold cyan]Rozpoczynam Fazę 3: Skanowanie Infrastruktury[/bold cyan]")
    )
    all_findings = []

    hosts_with_ports = categorized_targets.get("hosts_with_ports", {})
    if not hosts_with_ports:
        utils.log_and_echo("Brak hostów z otwartymi portami.", "WARN")
        return []

    # 1. Nuclei Infra
    all_findings.extend(_run_nuclei_infra(hosts_with_ports))

    # 2. TestSSL.sh
    all_findings.extend(_run_testssl(hosts_with_ports))

    # 3. Nmap NSE
    for host, port_dicts in hosts_with_ports.items():
        ports = [p["port"] for p in port_dicts]
        all_findings.extend(_run_nmap_vuln_scripts(host, ports))

    utils.console.print(
        f"Faza 3 zakończona. Całkowita liczba znalezisk: [bold green]{len(all_findings)}[/bold green]"
    )
    return all_findings
