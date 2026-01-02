# /usr/local/share/vulnmap/phase2_active_app.py

import json
import os
import subprocess
import time
import re
from typing import Any, Dict, List, Optional

import vulnmap_config as config
import vulnmap_utils as utils
import waf_evasion
from rich.panel import Panel
from vulnmap_utils import WafHealthMonitor, WafStatus

# Stałe ścieżki
LFIMAP_PATH = os.path.join(config.SHARE_DIR, "lfimap", "lfimap.py")


def _check_waf_and_sleep(waf_monitor: WafHealthMonitor, tool_name: str) -> bool:
    """
    Sprawdza stan WAF, zarządza pauzami i wykonuje losowe opóźnienie (Sleep).
    Zwraca False, jeśli należy przerwać skanowanie danego celu.
    """
    # 1. Obowiązkowe losowe opóźnienie (Evasion)
    waf_evasion.random_sleep()

    # 2. Sprawdzenie stanu monitora
    status = waf_monitor.get_status()
    
    if status == WafStatus.RED:
        utils.log_and_echo(
            f"[{tool_name}] WAF ZABLOKOWANY (RED)! Wstrzymuję działanie...", "ERROR"
        )
        # Pętla oczekiwania na zdjęcie blokady
        while waf_monitor.get_status() == WafStatus.RED:
            time.sleep(30)
        utils.log_and_echo(f"[{tool_name}] WAF Status wrócił do normy. Wznawiam.", "INFO")
        return True

    if status == WafStatus.YELLOW:
        utils.log_and_echo(f"[{tool_name}] WAF PODEJRZANY (YELLOW). Zwalniam dwukrotnie.", "WARN")
        # Dodatkowe opóźnienie w przypadku problemów
        time.sleep(config.WAF_CHECK_INTERVAL_MAX_SAFE)
    
    return True


def _detect_potential_idor(targets: List[str]) -> List[Dict[str, Any]]:
    """Pasywna analiza URLi w poszukiwaniu potencjalnych IDOR-ów."""
    findings = []
    # Wzorce parametrów sugerujące IDOR
    idor_patterns = [
        r"id=", r"user_id=", r"account=", r"invoice=", 
        r"order_num=", r"profile_id=", r"doc_id=", r"customer="
    ]

    suspicious_urls = []
    for url in targets:
        for pattern in idor_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_urls.append(url)
                break

    if suspicious_urls:
        sample = suspicious_urls[:5]
        findings.append(
            {
                "vulnerability": "Potential IDOR Endpoint",
                "severity": "low",
                "target": "Multiple Endpoints",
                "details": {
                    "description": f"Detected parameters commonly associated with IDOR in {len(suspicious_urls)} URLs.",
                    "sample_urls": sample,
                },
                "remediation": "Manual Verification Required. Check authorization logic when changing these IDs between users.",
                "source": "VulnMap Heuristics",
            }
        )
    return findings


def _orchestrate_wpscan(
    root_urls: List[str], technologies: List[str], waf_monitor: WafHealthMonitor
) -> List[Dict[str, Any]]:
    """Uruchamia WPScan tylko jeśli wykryto WordPressa."""
    findings = []
    
    is_wp = any("wordpress" in tech.lower() for tech in technologies)
    if not is_wp:
        return []

    utils.log_and_echo("Wykryto WordPress. Uruchamiam WPScan (Stealth Mode)...", "INFO")

    for url in root_urls:
        if not _check_waf_and_sleep(waf_monitor, "WPScan"):
            continue

        # Generowanie nagłówków dla spójności
        headers = waf_evasion.get_random_browser_headers(url)
        ua = headers.get("User-Agent", "Mozilla/5.0")

        command = [
            "wpscan",
            "--url", url,
            "--enumerate", "p,t,u",
            "--format", "json",
            "--user-agent", ua,
            "--disable-tls-checks",
            "--random-user-agent" # WPScan ma wbudowaną rotację, ale nadpisujemy naszym głównym
        ]

        # W trybie bezpiecznym zwalniamy drastycznie
        if config.SAFE_MODE:
            command.extend(["--throttle", "5000"])  # 5 sekund między żądaniami
            command.extend(["--stealthy"])
        else:
            command.extend(["--throttle", "1000"])

        try:
            process = subprocess.run(
                command, capture_output=True, text=True, timeout=config.TOOL_TIMEOUT_SECONDS
            )
            try:
                data = json.loads(process.stdout)
                
                # Tylko interesujące znaleziska
                if "users" in data and data["users"]:
                    usernames = [u.get("name") for u in data["users"].values()]
                    findings.append({
                        "vulnerability": "WordPress User Enumeration",
                        "severity": "medium",
                        "target": url,
                        "details": f"Found users: {', '.join(usernames)}",
                        "remediation": "Disable REST API user enumeration.",
                        "source": "WPScan",
                    })

                version = data.get("version", {}).get("number")
                if version:
                    findings.append({
                        "vulnerability": f"WordPress Version ({version})",
                        "severity": "info",
                        "target": url,
                        "details": f"Detected version: {version}",
                        "remediation": "Ensure WP is up to date.",
                        "source": "WPScan",
                    })

            except json.JSONDecodeError:
                pass
        except Exception as e:
            utils.log_and_echo(f"Błąd WPScan: {e}", "DEBUG")

    return findings


def _orchestrate_dalfox(
    targets: List[str], waf_monitor: WafHealthMonitor
) -> List[Dict[str, Any]]:
    """Uruchamia Dalfox (XSS Scanner) z zaawansowaną konfiguracją Evasion."""
    findings = []
    if not targets:
        return []

    utils.log_and_echo("Rozpoczynam skanowanie XSS (Dalfox) - Low and Slow...", "INFO")

    # Dalfox w trybie pipe jest szybki, ale niebezpieczny dla WAF.
    # W trybie SAFE musimy ograniczyć współbieżność.
    
    # Przygotowanie celów (tylko te z parametrami)
    targets_str = "\n".join(targets)

    delay_ms = int(config.REQUEST_DELAY_SAFE * 1000) if config.SAFE_MODE else int(config.REQUEST_DELAY_NORMAL * 1000)
    workers = 1 if config.SAFE_MODE else 2

    command = [
        "dalfox", "pipe",
        "--format", "json",
        "--silence",
        "--skip-mining-dom",
        "--ignore-return", "302,403,404,500,503", # Ignoruj błędy WAF/Server
        "--delay", str(delay_ms),
        "--worker", str(workers)
    ]

    # Wstrzykiwanie nagłówków z waf_evasion
    headers = waf_evasion.get_random_browser_headers()
    for k, v in headers.items():
        command.extend(["--header", f"{k}: {v}"])
        if k == "User-Agent":
             command.extend(["--user-agent", v])

    # Cookie (jeśli zdefiniowane w env lub configu, tu placeholder)
    # command.extend(["--cookie", "session=..."])

    _check_waf_and_sleep(waf_monitor, "Dalfox-Init")

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(
            input=targets_str, timeout=config.TOOL_TIMEOUT_SECONDS
        )

        for line in stdout.splitlines():
            try:
                data = json.loads(line)
                findings.append(
                    {
                        "vulnerability": f"XSS ({data.get('type', 'Reflected')})",
                        "severity": data.get("severity", "high").lower(),
                        "target": data.get("url"),
                        "details": {
                            "payload": data.get("payload"),
                            "evidence": data.get("evidence"),
                        },
                        "remediation": "Context-aware output encoding.",
                        "source": "Dalfox",
                    }
                )
            except json.JSONDecodeError:
                continue

    except Exception as e:
        utils.log_and_echo(f"Błąd Dalfox: {e}", "ERROR")

    return findings


def _orchestrate_lfimap(
    targets: List[str], waf_monitor: WafHealthMonitor
) -> List[Dict[str, Any]]:
    """Uruchamia LFIMap z opóźnieniami."""
    findings = []
    if not targets or not os.path.exists(LFIMAP_PATH):
        if not os.path.exists(LFIMAP_PATH):
            utils.log_and_echo("LFIMap brak. Pomiń.", "WARN")
        return []

    utils.log_and_echo("Skanowanie LFI...", "INFO")
    
    # Ograniczenie liczby celów
    limit = 3 if config.SAFE_MODE else 10
    targets_to_scan = targets[:limit]

    for url in targets_to_scan:
        if not _check_waf_and_sleep(waf_monitor, "LFIMap"):
            continue

        delay_ms = int(config.REQUEST_DELAY_SAFE * 1000) if config.SAFE_MODE else 500
        
        # Generowanie nagłówków
        headers = waf_evasion.get_random_browser_headers(url)
        ua = headers.get("User-Agent")

        # LFIMap argumenty
        command = [
            "python3", LFIMAP_PATH,
            "-U", url,
            "--no-stop",
            "--delay", str(delay_ms),
            "-a", ua # User-Agent
        ]

        try:
            process = subprocess.run(
                command, capture_output=True, text=True, timeout=300
            )
            # Proste parsowanie
            if "[+]" in process.stdout:
                vuln_lines = [l.strip() for l in process.stdout.splitlines() if "[+]" in l]
                if vuln_lines:
                    findings.append({
                        "vulnerability": "Local File Inclusion (LFI)",
                        "severity": "critical",
                        "target": url,
                        "details": "\n".join(vuln_lines[:3]),
                        "remediation": "Validate filenames against allowlist.",
                        "source": "LFIMap",
                    })
        except Exception:
            pass

    return findings


def _orchestrate_sqlmap(
    targets: List[str], waf_monitor: WafHealthMonitor
) -> List[Dict[str, Any]]:
    """
    Orkiestracja SQLMap z silnym naciskiem na WAF Evasion.
    """
    findings = []
    if not targets:
        return []

    utils.log_and_echo("Skanowanie SQL Injection (SQLMap Stealth)...", "INFO")

    # W trybie bezpiecznym skanujemy tylko kilka najbardziej obiecujących URLi
    limit = 3 if config.SAFE_MODE else 10
    targets_to_scan = targets[:limit]

    for url in targets_to_scan:
        # Sprawdzenie WAF przed uruchomieniem instancji SQLMap
        if not _check_waf_and_sleep(waf_monitor, "SQLMap"):
            continue

        # Pobieranie skryptów tamper i nagłówków
        tamper_scripts = waf_evasion.select_sqlmap_tamper_scripts()
        headers = waf_evasion.get_random_browser_headers(url)
        
        command = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--banner",
            "--fail-fast", # Przerywa przy błędach połączenia
            "--random-agent", # SQLMap ma swoją dobrą bazę agentów, ale można nadpisać
            "--skip-waf", # Próba ominięcia heurystyk sprawdzających WAF (paradoksalnie pomaga)
        ]

        # Konfiguracja Evasion
        if tamper_scripts:
            command.append(f"--tamper={','.join(tamper_scripts)}")
        
        if config.SAFE_MODE:
            command.extend([
                "--delay", str(config.REQUEST_DELAY_SAFE),
                "--level", "1", 
                "--risk", "1",
                "--threads", "1",
                "--timeout", "15"
            ])
        else:
            command.extend([
                "--delay", str(config.REQUEST_DELAY_NORMAL),
                "--level", "2",
                "--risk", "1"
            ])

        # Katalog wyjściowy
        sqlmap_out_dir = os.path.join(config.REPORT_DIR, "sqlmap_raw")
        command.append(f"--output-dir={sqlmap_out_dir}")

        try:
            process = subprocess.run(
                command, capture_output=True, text=True, timeout=600
            )

            if "Place:" in process.stdout and "Parameter:" in process.stdout:
                findings.append({
                    "vulnerability": "SQL Injection",
                    "severity": "critical",
                    "target": url,
                    "details": "SQLMap confirmed injection. Check output logs.",
                    "remediation": "Use prepared statements.",
                    "source": "SQLMap",
                })
        except subprocess.TimeoutExpired:
            utils.log_and_echo(f"SQLMap timeout dla {url}", "WARN")

    return findings


def start_active_scan(
    categorized_targets: Dict[str, Any], waf_monitor: WafHealthMonitor
) -> List[Dict[str, Any]]:
    """
    Punkt wejściowy dla Fazy 2.
    """
    utils.console.print(
        Panel(
            "[bold cyan]Rozpoczynam Fazę 2: Aktywne Skanowanie (OPSEC MODE)[/bold cyan]"
        )
    )
    all_findings = []

    urls_with_params = categorized_targets.get("urls_with_params", [])
    root_urls = categorized_targets.get("root_urls", [])
    technologies = list(categorized_targets.get("technologies", []))

    if not urls_with_params:
        utils.log_and_echo("Brak URLi z parametrami. Faza 2 ograniczona.", "WARN")

    # 1. Pasywna detekcja IDOR (Bezpieczne)
    all_findings.extend(_detect_potential_idor(urls_with_params))

    # 2. WPScan (Jeśli dotyczy)
    all_findings.extend(_orchestrate_wpscan(root_urls, technologies, waf_monitor))

    # 3. Dalfox (XSS) - Z opóźnieniami
    all_findings.extend(_orchestrate_dalfox(urls_with_params, waf_monitor))

    # 4. LFIMap
    all_findings.extend(_orchestrate_lfimap(urls_with_params, waf_monitor))

    # 5. SQLMap (Najbardziej ryzykowne - na końcu)
    all_findings.extend(_orchestrate_sqlmap(urls_with_params, waf_monitor))

    utils.console.print(
        f"Faza 2 zakończona. Całkowita liczba znalezisk: [bold green]{len(all_findings)}[/bold green]"
    )
    return all_findings
