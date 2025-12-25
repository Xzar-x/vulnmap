# /usr/local/share/vulnmap/phase2_active_app.py

import json
import os
import shutil
import subprocess
import time
import random
import re
import sys
from typing import Any, Dict, List, Optional

import vulnmap_config as config
import vulnmap_utils as utils
import waf_evasion
from rich.panel import Panel
from vulnmap_utils import WafHealthMonitor, WafStatus

# Stałe ścieżki
LFIMAP_PATH = os.path.join(config.SHARE_DIR, "lfimap", "lfimap.py")

def _check_waf_status(waf_monitor: WafHealthMonitor, tool_name: str) -> bool:
    """Sprawdza stan WAF i wstrzymuje działanie jeśli potrzeba."""
    status = waf_monitor.get_status()
    
    if status == WafStatus.RED:
        utils.log_and_echo(f"[{tool_name}] WAF ZABLOKOWANY! Wstrzymuję skanowanie.", "ERROR")
        
        wait_cycles = 0
        max_wait_cycles = 10 # Czekamy do 5 minut (10 * 30s)
        
        while waf_monitor.get_status() == WafStatus.RED:
            time.sleep(30)
            wait_cycles += 1
            utils.log_and_echo(f"[{tool_name}] Czekam na zdjęcie blokady... ({wait_cycles}/{max_wait_cycles})", "DEBUG")
            
            if wait_cycles >= max_wait_cycles:
                utils.console.print("\n[bold red]!!! ALARM: Blokada WAF trwa zbyt długo !!![/bold red]")
                return False

        utils.log_and_echo(f"[{tool_name}] Blokada ustąpiła. Wznawiam.", "INFO")
    
    if status == WafStatus.YELLOW:
        utils.log_and_echo(f"[{tool_name}] WAF PODEJRZANY. Zwalniam.", "WARN")
        time.sleep(config.WAF_CHECK_INTERVAL_MAX_SAFE)
        
    return True

def _cool_down(seconds=5, reason="Odpoczynek między narzędziami"):
    """Wstawia sztuczne opóźnienie, aby zmylić systemy analizy behawioralnej."""
    if config.SAFE_MODE:
        seconds *= 2
    utils.log_and_echo(f"... {reason} ({seconds}s) ...", "DEBUG")
    time.sleep(seconds)

def _detect_potential_idor(targets: List[str]) -> List[Dict[str, Any]]:
    """Pasywna analiza URLi w poszukiwaniu potencjalnych IDOR-ów."""
    findings = []
    idor_patterns = [r"id=", r"user_id=", r"account=", r"invoice=", r"order_num=", r"profile_id="]
    
    suspicious_urls = []
    for url in targets:
        for pattern in idor_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_urls.append(url)
                break
    
    if suspicious_urls:
        sample = suspicious_urls[:5]
        findings.append({
            "vulnerability": "Potential IDOR Endpoint",
            "severity": "low",
            "target": "Multiple Endpoints",
            "details": {
                "description": f"Detected parameters commonly associated with IDOR in {len(suspicious_urls)} URLs.",
                "sample_urls": sample
            },
            "remediation": "Manual Verification Required.",
            "source": "VulnMap Heuristics"
        })
    return findings

def _orchestrate_wpscan(root_urls: List[str], technologies: List[str], waf_monitor: WafHealthMonitor) -> List[Dict[str, Any]]:
    """Uruchamia WPScan tylko jeśli wykryto WordPressa."""
    findings = []
    is_wp = any("wordpress" in tech.lower() for tech in technologies)
    if not is_wp:
        return []

    utils.log_and_echo("Wykryto WordPress. Uruchamiam WPScan...", "INFO")
    
    for url in root_urls:
        if not _check_waf_status(waf_monitor, "WPScan"): break
        
        # WPScan jest głośny, więc w trybie stealth ograniczamy go drastycznie
        command = [
            "wpscan", "--url", url,
            "--enumerate", "u", # Tylko userzy, pomin pluginy w trybie stealth
            "--format", "json",
            "--random-user-agent", # KLUCZOWE
            "--disable-tls-checks",
            "--connect-timeout", "30",
            "--request-timeout", "30"
        ]
        
        if config.SAFE_MODE:
            command.extend(["--throttle", "5000"]) # 5 sekund między requestami!
            command.extend(["--stealthy"]) # Alias dla kilku bezpiecznych opcji
        else:
             command.extend(["--throttle", "1000"])

        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=600)
            try:
                data = json.loads(process.stdout)
                users = data.get("users", {})
                if users:
                    usernames = [u.get("name") for u in users.values()]
                    findings.append({
                        "vulnerability": "WordPress User Enumeration",
                        "severity": "medium",
                        "target": url,
                        "details": f"Found users: {', '.join(usernames)}",
                        "remediation": "Disable user enumeration.",
                        "source": "WPScan"
                    })
            except json.JSONDecodeError:
                pass 
        except Exception as e:
            utils.log_and_echo(f"Błąd WPScan: {e}", "ERROR")

    return findings

def _orchestrate_dalfox(targets: List[str], waf_monitor: WafHealthMonitor) -> List[Dict[str, Any]]:
    """Uruchamia Dalfox (XSS Scanner)."""
    findings = []
    if not targets: return []

    utils.log_and_echo("Rozpoczynam skanowanie XSS (Dalfox)...", "INFO")
    
    # Mniejsze paczki URLi
    chunk_size = 3 if config.SAFE_MODE else 10
    
    for i in range(0, len(targets), chunk_size):
        chunk = targets[i:i + chunk_size]
        
        if not _check_waf_status(waf_monitor, "Dalfox"): break
        _cool_down(2, "Odstęp między paczkami Dalfox")

        targets_str = "\n".join(chunk)
        command = ["dalfox", "pipe", "--format", "json", "--silence", "--skip-mining-dom", "--ignore-return", "302,403,404"]
        
        if config.SAFE_MODE:
            command.extend(["--delay", "3000"]) # 3s delay
        else:
            command.extend(["--delay", "500"]) # 0.5s delay domyślnie
        
        headers = waf_evasion.get_random_browser_headers()
        for k, v in headers.items():
            command.extend(["--header", f"{k}: {v}"])
        
        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(input=targets_str, timeout=config.TOOL_TIMEOUT_SECONDS)
            
            for line in stdout.splitlines():
                try:
                    data = json.loads(line)
                    findings.append({
                        "vulnerability": f"XSS ({data.get('type', 'Reflected')})",
                        "severity": data.get("severity", "high").lower(),
                        "target": data.get("url"),
                        "details": {"payload": data.get('payload')},
                        "remediation": "Sanitize input.",
                        "source": "Dalfox"
                    })
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            utils.log_and_echo(f"Błąd Dalfox: {e}", "ERROR")

    return findings

def _orchestrate_lfimap(targets: List[str], waf_monitor: WafHealthMonitor) -> List[Dict[str, Any]]:
    """Uruchamia LFIMap."""
    findings = []
    lfimap_cmd = "lfimap"
    if shutil.which(lfimap_cmd) is None:
         if os.path.exists(LFIMAP_PATH):
             lfimap_cmd = f"python3 {LFIMAP_PATH}"
         else:
             return []

    utils.log_and_echo("Rozpoczynam skanowanie LFI (LFIMap)...", "INFO")
    
    targets_to_scan = targets[:3] if config.SAFE_MODE else targets[:10]

    for url in targets_to_scan:
        if not _check_waf_status(waf_monitor, "LFIMap"): break
        _cool_down(3, "Odstęp przed LFImap")
        
        # --- NAPRAWA: Dodanie losowego User-Agenta ---
        ua_headers = waf_evasion.get_random_browser_headers()
        user_agent = ua_headers.get("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        
        command = ["lfimap", "-U", url, "--no-stop", "-a", user_agent]
        
        if config.SAFE_MODE:
            command.extend(["--delay", "2000"])
        else:
            command.extend(["--delay", "500"])
        
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=300)
            if "[+]" in process.stdout:
                vuln_lines = [line.strip() for line in process.stdout.splitlines() if "[+]" in line]
                if vuln_lines:
                     findings.append({
                        "vulnerability": "LFI (LFIMap)",
                        "severity": "critical",
                        "target": url,
                        "details": "\n".join(vuln_lines[:3]),
                        "remediation": "Validate filenames.",
                        "source": "LFIMap"
                    })
        except Exception as e:
            utils.log_and_echo(f"Błąd LFIMap: {e}", "DEBUG")

    return findings

def _orchestrate_sqlmap(targets: List[str], waf_monitor: WafHealthMonitor) -> List[Dict[str, Any]]:
    """Orkiestruje SQLMap."""
    findings = []
    if not targets: return []

    utils.log_and_echo("Rozpoczynam skanowanie SQL Injection (SQLMap)...", "INFO")
    
    # Bardzo ostrożny dobór celów
    targets_to_scan = targets[:3] if config.SAFE_MODE else targets[:10]

    for url in targets_to_scan:
        if not _check_waf_status(waf_monitor, "SQLMap"): break
        _cool_down(5, "Odstęp przed SQLMap")
            
        command = ["sqlmap", "-u", url, "--batch", "--banner", "--fail-fast"]
        
        if config.SAFE_MODE:
            tamper_scripts = waf_evasion.select_sqlmap_tamper_scripts()
            if tamper_scripts:
                command.append(f"--tamper={','.join(tamper_scripts)}")
            # Zwiększone bezpieczeństwo
            command.extend(["--random-agent", "--delay=5", "--level=1", "--risk=1"])
        else:
            command.extend(["--random-agent", "--delay=1", "--level=2", "--risk=1"])

        sqlmap_out_dir = os.path.join(config.REPORT_DIR, "sqlmap_raw")
        command.append(f"--output-dir={sqlmap_out_dir}")

        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=300)
            if "Place:" in process.stdout:
                findings.append({
                    "vulnerability": "SQL Injection",
                    "severity": "critical",
                    "target": url,
                    "details": "SQLMap confirmed injection.",
                    "remediation": "Prepared statements.",
                    "source": "SQLMap"
                })
        except subprocess.TimeoutExpired:
            utils.log_and_echo(f"SQLMap timeout dla {url}", "WARN")

    return findings

def start_active_scan(categorized_targets: Dict[str, Any], waf_monitor: WafHealthMonitor) -> List[Dict[str, Any]]:
    """Punkt wejściowy dla Fazy 2."""
    utils.console.print(Panel("[bold cyan]Rozpoczynam Fazę 2: Aktywne Skanowanie Aplikacji Webowych[/bold cyan]"))
    
    # Wstępna pauza, żeby monitor zdążył ustalić baseline
    utils.console.print("[yellow]Kalibracja monitora WAF... (czekam 5s)[/yellow]")
    time.sleep(5)
    
    if waf_monitor.get_status() == WafStatus.RED:
        utils.console.print("[bold red]Start anulowany - cel już jest zbanowany lub niedostępny![/bold red]")
        return []

    all_findings = []
    urls_with_params = categorized_targets.get("urls_with_params", [])
    root_urls = categorized_targets.get("root_urls", [])
    technologies = list(categorized_targets.get("technologies", []))
    
    # 1. Pasywna detekcja (Bezpieczna)
    all_findings.extend(_detect_potential_idor(urls_with_params))

    # 2. WPScan (Ryzykowny - teraz z throttlingiem)
    all_findings.extend(_orchestrate_wpscan(root_urls, technologies, waf_monitor))
    _cool_down(5, "Odpoczynek po WPScan")

    # 3. Dalfox (Średnie ryzyko)
    all_findings.extend(_orchestrate_dalfox(urls_with_params, waf_monitor))
    _cool_down(5, "Odpoczynek po Dalfox")

    # 4. LFIMap (Wysokie ryzyko - teraz z naprawionym User-Agentem)
    all_findings.extend(_orchestrate_lfimap(urls_with_params, waf_monitor))
    _cool_down(5, "Odpoczynek po LFIMap")

    # 5. SQLMap (Najwyższe ryzyko - na końcu)
    all_findings.extend(_orchestrate_sqlmap(urls_with_params, waf_monitor))
    
    utils.console.print(f"Faza 2 zakończona. Całkowita liczba znalezisk: [bold green]{len(all_findings)}[/bold green]")
    return all_findings