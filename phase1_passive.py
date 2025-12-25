# /usr/local/share/vulnmap/phase1_passive.py

import os
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
    with open(output_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                data = json.loads(line)
                finding = {
                    "vulnerability": data.get("info", {}).get("name"),
                    "severity": data.get("info", {}).get("severity"),
                    "target": data.get("host"),
                    "details": data.get("matcher-name")
                    or data.get("extracted-results"),
                    "remediation": data.get("info", {}).get("remediation"),
                    "source": "Nuclei",
                }
                findings.append(finding)
            except json.JSONDecodeError:
                continue
    return findings


def _run_nuclei_passive(root_urls: List[str]) -> List[Dict[str, Any]]:
    """Uruchamia Nuclei z bezpiecznymi szablonami do skanowania pasywnego."""
    utils.log_and_echo(
        "Uruchamiam pasywne skanowanie Nuclei (misconfigurations, technologies)...",
        "INFO",
    )

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp_file:
        tmp_file.write("\n".join(root_urls))
        targets_file = tmp_file.name

    output_file = os.path.join(config.REPORT_DIR, "nuclei_passive_results.json")

    command = [
        "nuclei",
        "-l",
        targets_file,
        "-t",
        "technologies/",
        "misconfiguration/",  # Przykładowe bezpieczne szablony
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
    ]

    try:
        subprocess.run(command, timeout=config.TOOL_TIMEOUT_SECONDS)
        findings = _parse_nuclei_output(output_file)
        utils.log_and_echo(
            f"Nuclei (pasywne) zakończył. Znaleziono {len(findings)} potencjalnych problemów.",
            "INFO",
        )
        return findings
    except subprocess.TimeoutExpired:
        utils.log_and_echo(
            "Pasywne skanowanie Nuclei przekroczyło limit czasu.", "WARN"
        )
    except Exception as e:
        utils.log_and_echo(f"Błąd podczas pasywnego skanowania Nuclei: {e}", "ERROR")
    finally:
        os.remove(targets_file)

    return []


def start_passive_scan(categorized_targets: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Punkt wejściowy dla Fazy 1. Uruchamia wszystkie pasywne skanery.
    Zwraca listę znalezionych problemów.
    """
    utils.console.print(
        Panel(
            "[bold cyan]Rozpoczynam Fazę 1: Skanowanie Pasywne i Konfiguracyjne[/bold cyan]"
        )
    )
    all_findings = []

    root_urls = categorized_targets.get("root_urls", [])
    if not root_urls:
        utils.log_and_echo("Brak celów do skanowania pasywnego w Fazie 1.", "WARN")
        return []

    # Uruchomienie skanowania Nuclei
    nuclei_findings = _run_nuclei_passive(root_urls)
    all_findings.extend(nuclei_findings)

    # TODO: Dodać w przyszłości inne skanery, np. testssl.sh
    # testssl_findings = _run_testssl(hosts)
    # all_findings.extend(testssl_findings)

    utils.console.print(
        f"Faza 1 zakończona. Całkowita liczba znalezisk: [bold green]{len(all_findings)}[/bold green]"
    )
    return all_findings
