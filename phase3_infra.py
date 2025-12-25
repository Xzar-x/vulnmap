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

# Importujemy funkcję pomocniczą z Phase 1 jeśli jest dostępna, lub definiujemy lokalnie
# Dla pewności i autonomii pliku, zdefiniujemy prostą wersję tutaj.
def _get_template_path_infra(category: str) -> str:
    """Zwraca ścieżkę do szablonu, obsługując różne wersje struktury katalogów."""
    # Struktura v10 (często w root lub http/network)
    paths_to_check = [
        os.path.join(config.NUCLEI_TEMPLATES_DIR, category),
        os.path.join(config.NUCLEI_TEMPLATES_DIR, "http", category), # Niektóre mogą być w http
        os.path.join(config.NUCLEI_TEMPLATES_DIR, "network", category) # Dla specyficznych sieciowych
    ]
    
    for p in paths_to_check:
        if os.path.exists(p):
            return p
            
    return category # Fallback

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
    
    # Budowanie listy szablonów
    categories = ["network", "ssl", "dns", "file"]
    templates_args = []
    for cat in categories:
        path = _get_template_path_infra(cat)
        if os.path.exists(path):
            templates_args.extend(["-t", path])
    
    # Jeśli nie znaleźliśmy ścieżek, użyj nazw domyślnych
    if not templates_args:
         templates_args = ["-t", "network/", "-t", "ssl/", "-t", "dns/"]

    command = [
        "nuclei",
        "-l", targets_file,
        "-json", "-o", output_file,
        "-silent",
        "-rate-limit", str(config.NUCLEI_RATE_LIMIT_SAFE if config.SAFE_MODE else config.NUCLEI_RATE_LIMIT)
    ] + templates_args
    
    try:
        utils.log_and_echo(f"Komenda Nuclei (Infra): {' '.join(command)}", "DEBUG")
        subprocess.run(command, timeout=config.TOOL_TIMEOUT_SECONDS)
        
        # Import parsera (dla czystości)
        from phase1_passive import _parse_nuclei_output
        findings = _parse_nuclei_output(output_file)
        utils.log_and_echo(f"Nuclei (infra) zakończył. Znaleziono {len(findings)} potencjalnych problemów.", "INFO")
        return findings
    except subprocess.TimeoutExpired:
        utils.log_and_echo("Skanowanie Nuclei (infra) przekroczyło limit czasu.", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Błąd podczas skanowania Nuclei (infra): {e}", "ERROR")
    finally:
        if os.path.exists(targets_file):
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