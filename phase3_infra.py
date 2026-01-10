# /usr/local/share/vulnmap/phase3_infra.py

import json
import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Union

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


def _extract_port_number(port_entry: Union[int, str, Dict]) -> int:
    """Bezpiecznie wyciąga numer portu z różnych formatów (int, dict, str)."""
    try:
        if isinstance(port_entry, dict):
            return int(port_entry.get("port", 0))
        return int(port_entry)
    except (ValueError, TypeError):
        return 0


def _run_testssl(hosts_map: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
    """Uruchamia testssl.sh dla hostów z portem 443."""
    findings = []
    if not os.path.exists(TESTSSL_PATH):
        utils.log_and_echo("testssl.sh nie znaleziony (uruchom install.py).", "WARN")
        return []

    # Filtrujemy tylko hosty z HTTPS (443)
    ssl_targets = []
    for host, ports in hosts_map.items():
        if not isinstance(ports, list):
            continue

        for p in ports:
            port_num = _extract_port_number(p)
            if port_num == 443:
                ssl_targets.append(host)
                break

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

        # NOWOŚĆ: Logowanie komendy
        cmd_str = " ".join(command)
        utils.log_and_echo(f"Komenda TestSSL: {cmd_str}", "INFO")

        try:
            # Spinner dla testssl.sh
            with utils.console.status(
                f"[bold green]Analiza SSL/TLS dla: {host}...[/bold green]",
                spinner="dots",
            ):
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

    # NOWOŚĆ: Logowanie komendy
    cmd_str = " ".join(command)
    utils.log_and_echo(f"Komenda Nmap: {cmd_str}", "INFO")

    try:
        # Spinner dla Nmapa
        with utils.console.status(
            f"[bold green]Nmap NSE skanuje {host}...[/bold green]",
            spinner="bouncingBar",
        ):
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=config.TOOL_TIMEOUT_SECONDS,
            )
        return _parse_nmap_vuln_output(process.stdout)
    except subprocess.TimeoutExpired:
        utils.log_and_echo(f"Skanowanie Nmap NSE dla {host} timeout.", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Błąd Nmap NSE dla {host}: {e}", "ERROR")
    return []


def _run_nuclei_infra(hosts_map: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
    """Uruchamia Nuclei z szablonami sieciowymi."""
    targets = []

    # Bezpieczne budowanie listy celów (host:port)
    for host, ports in hosts_map.items():
        if not isinstance(ports, list):
            continue
        for p in ports:
            port_num = _extract_port_number(p)
            if port_num > 0:
                targets.append(f"{host}:{port_num}")

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
        "-j",  # Używamy -j
        "-o",
        output_file,
        "-silent",
        "-nc",  # No color
        "-rate-limit",
        str(
            config.NUCLEI_RATE_LIMIT_SAFE
            if config.SAFE_MODE
            else config.NUCLEI_RATE_LIMIT
        ),
    ] + templates_args

    # NOWOŚĆ: Logowanie komendy
    cmd_str = " ".join(command)
    utils.log_and_echo(f"Komenda Nuclei Infra: {cmd_str}", "INFO")

    try:
        # POPRAWKA: Przekierowanie stdout/stderr do DEVNULL, aby wyciszyć "plucie" tekstem
        with utils.console.status(
            "[bold green]Nuclei sprawdza infrastrukturę...[/bold green]",
            spinner="dots12",
        ):
            subprocess.run(
                command,
                timeout=config.TOOL_TIMEOUT_SECONDS,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

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

    raw_hosts_data = categorized_targets.get("hosts_with_ports", {})

    # --- NORMALIZACJA DANYCH ---
    hosts_map = {}

    if "open_ports_by_host" in raw_hosts_data:
        hosts_map = raw_hosts_data["open_ports_by_host"]
    else:
        hosts_map = raw_hosts_data

    if not hosts_map:
        utils.log_and_echo("Brak hostów z otwartymi portami.", "WARN")
        return []

    # 1. Nuclei Infra
    all_findings.extend(_run_nuclei_infra(hosts_map))

    # 2. TestSSL.sh
    all_findings.extend(_run_testssl(hosts_map))

    # 3. Nmap NSE
    for host, raw_ports in hosts_map.items():
        if not isinstance(raw_ports, list):
            continue

        # Normalizacja listy portów do listy intów dla Nmapa
        clean_ports = []
        for p in raw_ports:
            clean_ports.append(_extract_port_number(p))

        # Filtruj zera
        clean_ports = [p for p in clean_ports if p > 0]

        if clean_ports:
            all_findings.extend(_run_nmap_vuln_scripts(host, clean_ports))

    utils.console.print(
        f"Faza 3 zakończona. Całkowita liczba znalezisk: [bold green]{len(all_findings)}[/bold green]"
    )
    return all_findings
