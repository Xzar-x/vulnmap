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

def _parse_nmap_vuln_output(nmap_output: str) -> List[Dict[str, Any]]:
    """Bardzo podstawowy parser dla skryptów Nmap --script=vuln."""
    findings = []
    # Wzorzec do znalezienia hosta
    host_pattern = re.compile(r"Nmap scan report for (\S+)")
    # Wzorzec do znalezienia podatności
    vuln_pattern = re.compile(r"^\s*\|\s+(\S+):(.+)\n\s*\|\s+State: VULNERABLE", re.MULTILINE)
    
    current_host = "N/A"
    host_match = host_pattern.search(nmap_output)
    if host_match:
        current_host = host_match.group(1)

    for match in vuln_pattern.finditer(nmap_output):
        script_name, title = match.groups()
        findings.append({
            "vulnerability": f"Nmap: {title.strip()}",
            "severity": "high", # Nmap nie podaje severity, więc zakładamy wysokie
            "target": current_host,
            "details": f"Nmap script '{script_name}' reported a vulnerability.",
            "remediation": "Check Nmap script documentation for remediation steps.",
            "source": "Nmap NSE",
        })
    return findings

def _run_nmap_vuln_scripts(host: str, ports: List[int]) -> List[Dict[str, Any]]:
    """Uruchamia Nmap z flagą --script=vuln na określonych portach."""
    if not ports:
        return []
    
    port_str = ",".join(map(str, ports))
    utils.log_and_echo(f"Uruchamiam Nmap NSE (vuln) dla {host} na portach: {port_str}", "INFO")
    
    command = [
        "nmap",
        "-sV", # Potrzebne dla wielu skryptów
        "-Pn",
        "--script=vuln",
        "-p", port_str,
        host
    ]
    
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=config.TOOL_TIMEOUT_SECONDS
        )
        return _parse_nmap_vuln_output(process.stdout)
    except subprocess.TimeoutExpired:
        utils.log_and_echo(f"Skanowanie Nmap NSE dla {host} przekroczyło limit czasu.", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Błąd podczas skanowania Nmap NSE dla {host}: {e}", "ERROR")
        
    return []

def _run_nuclei_infra(hosts_with_ports: Dict[str, List[Dict]]) -> List[Dict[str, Any]]:
    """Uruchamia Nuclei z szablonami sieciowymi na hostach i portach."""
    targets = [f"{host}:{p['port']}" for host, ports in hosts_with_ports.items() for p in ports]
    if not targets:
        return []
        
    utils.log_and_echo("Uruchamiam skanowanie infrastruktury za pomocą Nuclei...", "INFO")

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".txt") as tmp_file:
        tmp_file.write("\n".join(targets))
        targets_file = tmp_file.name

    output_file = os.path.join(config.REPORT_DIR, "nuclei_infra_results.json")
    
    command = [
        "nuclei",
        "-l", targets_file,
        "-t", "network/", "ssl/", "dns/", "file/", # Przykładowe szablony infra
        "-json", "-o", output_file,
        "-silent",
        "-rate-limit", str(config.NUCLEI_RATE_LIMIT_SAFE if config.SAFE_MODE else config.NUCLEI_RATE_LIMIT)
    ]
    
    try:
        subprocess.run(command, timeout=config.TOOL_TIMEOUT_SECONDS)
        # Możemy użyć tej samej funkcji co w phase1_passive, ale dla czystości kodu jest tu zduplikowana
        # W przyszłości można ją przenieść do vulnmap_utils
        from phase1_passive import _parse_nuclei_output
        findings = _parse_nuclei_output(output_file)
        utils.log_and_echo(f"Nuclei (infra) zakończył. Znaleziono {len(findings)} potencjalnych problemów.", "INFO")
        return findings
    except subprocess.TimeoutExpired:
        utils.log_and_echo("Skanowanie Nuclei (infra) przekroczyło limit czasu.", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Błąd podczas skanowania Nuclei (infra): {e}", "ERROR")
    finally:
        os.remove(targets_file)
        
    return []


def start_infra_scan(categorized_targets: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Punkt wejściowy dla Fazy 3. Uruchamia skanery podatności na poziomie infrastruktury.
    """
    utils.console.print(Panel("[bold cyan]Rozpoczynam Fazę 3: Skanowanie Infrastruktury[/bold cyan]"))
    all_findings = []
    
    hosts_with_ports = categorized_targets.get("hosts_with_ports", {})
    if not hosts_with_ports:
        utils.log_and_echo("Brak hostów z otwartymi portami do skanowania w Fazie 3.", "WARN")
        return []

    # Skanowanie Nuclei (bardziej wydajne, bo na wszystkich celach naraz)
    nuclei_findings = _run_nuclei_infra(hosts_with_ports)
    all_findings.extend(nuclei_findings)
    
    # Skanowanie Nmap (per host)
    for host, port_dicts in hosts_with_ports.items():
        ports = [p['port'] for p in port_dicts]
        nmap_findings = _run_nmap_vuln_scripts(host, ports)
        all_findings.extend(nmap_findings)
    
    utils.console.print(f"Faza 3 zakończona. Całkowita liczba znalezisk: [bold green]{len(all_findings)}[/bold green]")
    return all_findings
