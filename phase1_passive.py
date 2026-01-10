# /usr/local/share/vulnmap/phase1_passive.py

import os
import json
import re
import subprocess
import tempfile
import requests
from typing import Any, Dict, List

import vulnmap_config as config
import vulnmap_utils as utils
import waf_evasion
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


def _get_template_path(category: str, subcategory: str = "http") -> str:
    """Pomocnicza funkcja do budowania ścieżki szablonu."""
    path_v2 = os.path.join(config.NUCLEI_TEMPLATES_DIR, subcategory, category)
    if os.path.exists(path_v2):
        return path_v2

    path_v1 = os.path.join(config.NUCLEI_TEMPLATES_DIR, category)
    if os.path.exists(path_v1):
        return path_v1

    return category


def _scan_js_secrets(js_urls: List[str]) -> List[Dict[str, Any]]:
    """
    Pobiera pliki JS (stosując zasady OPSEC) i skanuje je pod kątem hardcodowanych sekretów.
    """
    findings = []
    if not js_urls:
        return []

    utils.log_and_echo(
        f"Rozpoczynam skanowanie {len(js_urls)} plików JS pod kątem sekretów (Regex)...",
        "INFO",
    )

    # Limitujemy ilość skanowanych plików w trybie Safe, żeby nie tracić godzin
    max_files = 15 if config.SAFE_MODE else 50
    targets = js_urls[:max_files]

    # Spinner dla procesu analizy JS
    with utils.console.status(
        f"[bold green]Pobieranie i analiza {len(targets)} plików JS...[/bold green]",
        spinner="material",
    ):
        for url in targets:
            # 1. OPSEC: Opóźnienie przed pobraniem pliku
            waf_evasion.random_sleep()

            try:
                # 2. OPSEC: Fałszywe nagłówki
                headers = waf_evasion.get_random_browser_headers(url)

                # Pobieranie strumieniowe, żeby sprawdzić rozmiar
                with requests.get(
                    url, headers=headers, stream=True, timeout=10, verify=False
                ) as r:
                    if r.status_code != 200:
                        continue

                    # Sprawdzenie Content-Length
                    content_length = r.headers.get("Content-Length")
                    if (
                        content_length
                        and int(content_length) > config.JS_SCAN_MAX_SIZE_BYTES
                    ):
                        utils.log_and_echo(
                            f"Pomijam {url} - plik za duży ({content_length} bajtów)",
                            "DEBUG",
                        )
                        continue

                    # Pobranie treści (z limitem rozmiaru w pamięci)
                    content = r.text[: config.JS_SCAN_MAX_SIZE_BYTES]

                    # 3. Analiza Regex
                    for name, pattern in config.SECRETS_PATTERNS.items():
                        matches = list(re.finditer(pattern, content))
                        for match in matches:
                            secret_val = match.group(0)

                            # Pobranie kontekstu (trochę znaków przed i po)
                            start = max(0, match.start() - 20)
                            end = min(len(content), match.end() + 20)
                            context = content[start:end].replace("\n", " ")

                            # Redukcja szumu: pomijamy jeśli wygląda na zwykły ID w CSS lub HTML
                            if len(secret_val) < 8:
                                continue

                            findings.append(
                                {
                                    "vulnerability": f"Hardcoded Secret: {name}",
                                    "severity": "high",  # Wyciek sekretów to zazwyczaj High/Critical
                                    "target": url,
                                    "details": {
                                        "match": secret_val,
                                        "context": f"...{context}...",
                                        "pattern": name,
                                    },
                                    "remediation": "Revoke the key immediately and remove it from the code.",
                                    "source": "VulnMap JS Analyzer",
                                }
                            )

            except Exception as e:
                utils.log_and_echo(f"Błąd analizy JS {url}: {e}", "DEBUG")

    if findings:
        utils.log_and_echo(
            f"Znaleziono {len(findings)} potencjalnych sekretów w plikach JS!", "WARN"
        )

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

    tech_path = _get_template_path("technologies")
    misc_path = _get_template_path("misconfiguration")
    exposures_path = _get_template_path("exposures")

    templates_args = []
    if os.path.exists(tech_path):
        templates_args.extend(["-t", tech_path])
    if os.path.exists(misc_path):
        templates_args.extend(["-t", misc_path])
    if os.path.exists(exposures_path):
        templates_args.extend(["-t", exposures_path])

    if not templates_args:
        utils.log_and_echo(
            f"UWAGA: Nie znaleziono folderów szablonów w {config.NUCLEI_TEMPLATES_DIR}.",
            "WARN",
        )

    # Konfiguracja Rate Limit i Timeoutów (Anti-Hang / Stability)
    rate_limit = str(
        config.NUCLEI_RATE_LIMIT_SAFE if config.SAFE_MODE else config.NUCLEI_RATE_LIMIT
    )

    command = [
        "nuclei",
        "-l",
        targets_file,
        "-j",  # Format JSON
        "-o",
        output_file,
        "-silent",  # Tylko wyniki
        "-nc",  # Bez kolorów (dla parsera)
        "-disable-update-check",  # Przyspieszenie startu
        "-rate-limit",
        rate_limit,
        # --- Flagi Stabilności (Zapobieganie wiszeniu) ---
        "-timeout",
        "5",  # Krótki timeout (5s) na request
        "-retries",
        "1",  # Tylko 1 powtórzenie przy błędzie
        "-mhe",
        "10",  # Max Host Errors: Pomiń hosta po 10 błędach
    ] + templates_args

    # Logowanie komendy dla debugowania
    cmd_str = " ".join(command)
    utils.log_and_echo(f"Komenda Nuclei Passive: {cmd_str}", "INFO")

    try:
        # Używamy status spinnera, żeby użytkownik wiedział, że coś się dzieje
        with utils.console.status(
            "[bold green]Nuclei szuka błędów konfiguracji (to może chwilę potrwać)...[/bold green]",
            spinner="dots",
        ):
            subprocess.run(
                command,
                timeout=config.TOOL_TIMEOUT_SECONDS,
                stdout=subprocess.DEVNULL,  # Wyciszamy stdout, bo parsujemy plik
                stderr=subprocess.DEVNULL,  # Wyciszamy stderr (ew. błędy sieciowe Nuclei)
            )

        findings = _parse_nuclei_output(output_file)
        utils.log_and_echo(
            f"Nuclei (pasywne) zakończył. Znaleziono {len(findings)} problemów.", "INFO"
        )
        return findings
    except subprocess.TimeoutExpired:
        utils.log_and_echo(
            "Pasywne skanowanie Nuclei przekroczyło globalny limit czasu.", "WARN"
        )
    except Exception as e:
        utils.log_and_echo(f"Błąd podczas pasywnego skanowania Nuclei: {e}", "ERROR")
    finally:
        if os.path.exists(targets_file):
            os.remove(targets_file)

    return []


def start_passive_scan(categorized_targets: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Punkt wejściowy dla Fazy 1.
    """
    utils.console.print(
        Panel(
            "[bold cyan]Rozpoczynam Fazę 1: Skanowanie Pasywne i Secrets Hunting[/bold cyan]"
        )
    )
    all_findings = []

    root_urls = categorized_targets.get("root_urls", [])
    js_files = categorized_targets.get("js_files", [])

    if not root_urls:
        utils.log_and_echo("Brak celów do skanowania pasywnego w Fazie 1.", "WARN")
        return []

    # 1. Skanowanie Nuclei
    nuclei_findings = _run_nuclei_passive(root_urls)
    all_findings.extend(nuclei_findings)

    # 2. Skanowanie plików JS pod kątem sekretów
    if js_files:
        js_findings = _scan_js_secrets(js_files)
        all_findings.extend(js_findings)
    else:
        utils.log_and_echo("Brak plików JS do analizy.", "INFO")

    utils.console.print(
        f"Faza 1 zakończona. Całkowita liczba znalezisk: [bold green]{len(all_findings)}[/bold green]"
    )
    return all_findings
