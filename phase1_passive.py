# /usr/local/share/vulnmap/phase1_passive.py

import os
import json
import subprocess
import tempfile
from typing import Any, Dict, List

import vulnmap_config as config
import vulnmap_utils as utils
from rich.panel import Panel

def _parse_nuclei_output(output_file: str) -> List[Dict[str, Any]]:
    """Parsuje wyjście JSON z Nuclei i konwertuje na listę znalezisk."""
    findings = []
    if not os.path.exists(output_file):
        return findings
    with open(output_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                data = json.loads(line)
                finding = {
                    "vulnerability": data.get("info", {}).get("name"),
                    "severity": data.get("info", {}).get("severity"),
                    "target": data.get("host"),
                    "details": data.get("matcher-name") or data.get("extracted-results"),
                    "remediation": data.get("info", {}).get("remediation"),
                    "source": "Nuclei",
                }
                findings.append(finding)
            except json.JSONDecodeError:
                continue
    return findings

def _get_template_path(category: str, subcategory: str = "http") -> str:
    """
    Pomocnicza funkcja do budowania ścieżki szablonu.
    Sprawdza czy szablon jest w root (stare wersje) czy w podkatalogu np. http/ (nowe wersje).
    """
    # Ścieżka dla nowych wersji: templates/http/technologies
    path_v2 = os.path.join(config.NUCLEI_TEMPLATES_DIR, subcategory, category)
    if os.path.exists(path_v2):
        return path_v2
    
    # Ścieżka dla starych wersji: templates/technologies
    path_v1 = os.path.join(config.NUCLEI_TEMPLATES_DIR, category)
    if os.path.exists(path_v1):
        return path_v1
        
    # Fallback: zwracamy po prostu nazwę, licząc że Nuclei samo znajdzie
    return category

def _run_nuclei_passive(root_urls: List[str]) -> List[Dict[str, Any]]:
    """Uruchamia Nuclei z bezpiecznymi szablonami do skanowania pasywnego."""
    utils.log_and_echo("Uruchamiam pasywne skanowanie Nuclei (misconfigurations, technologies)...", "INFO")
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".txt") as tmp_file:
        tmp_file.write("\n".join(root_urls))
        targets_file = tmp_file.name

    output_file = os.path.join(config.REPORT_DIR, "nuclei_passive_results.json")
    
    # Pobieranie poprawnych ścieżek
    tech_path = _get_template_path("technologies")
    misc_path = _get_template_path("misconfiguration")
    
    # Weryfikacja czy ścieżki istnieją, żeby nie rzucać błędem Nuclei
    templates_args = []
    if os.path.exists(tech_path): templates_args.extend(["-t", tech_path])
    if os.path.exists(misc_path): templates_args.extend(["-t", misc_path])

    if not templates_args:
         utils.log_and_echo(f"UWAGA: Nie znaleziono folderów szablonów w {config.NUCLEI_TEMPLATES_DIR}. Uruchamiam bez flagi -t (domyślne skanowanie może trwać dłużej).", "WARN")
         # Ewentualnie można dodać ["-t", "technologies"] jako fallback dla wbudowanych mechanizmów
    
    command = [
        "nuclei",
        "-l", targets_file,
        "-json", "-o", output_file,
        "-silent",
        "-rate-limit", str(config.NUCLEI_RATE_LIMIT_SAFE if config.SAFE_MODE else config.NUCLEI_RATE_LIMIT)
    ] + templates_args
    
    try:
        utils.log_and_echo(f"Komenda Nuclei: {' '.join(command)}", "DEBUG")
        subprocess.run(command, timeout=config.TOOL_TIMEOUT_SECONDS)
        findings = _parse_nuclei_output(output_file)
        utils.log_and_echo(f"Nuclei (pasywne) zakończył. Znaleziono {len(findings)} potencjalnych problemów.", "INFO")
        return findings
    except subprocess.TimeoutExpired:
        utils.log_and_echo("Pasywne skanowanie Nuclei przekroczyło limit czasu.", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Błąd podczas pasywnego skanowania Nuclei: {e}", "ERROR")
    finally:
        if os.path.exists(targets_file):
            os.remove(targets_file)
        
    return []

def start_passive_scan(categorized_targets: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Punkt wejściowy dla Fazy 1. Uruchamia wszystkie pasywne skanery.
    Zwraca listę znalezionych problemów.
    """
    utils.console.print(Panel("[bold cyan]Rozpoczynam Fazę 1: Skanowanie Pasywne i Konfiguracyjne[/bold cyan]"))
    all_findings = []
    
    root_urls = categorized_targets.get("root_urls", [])
    if not root_urls:
        utils.log_and_echo("Brak celów do skanowania pasywnego w Fazie 1.", "WARN")
        return []

    # Uruchomienie skanowania Nuclei
    nuclei_findings = _run_nuclei_passive(root_urls)
    all_findings.extend(nuclei_findings)
    
    utils.console.print(f"Faza 1 zakończona. Całkowita liczba znalezisk: [bold green]{len(all_findings)}[/bold green]")
    return all_findings