# /usr/local/share/vulnmap/phase2_active_app.py

import subprocess
import time
from typing import Any, Dict, List

import vulnmap_config as config
import vulnmap_utils as utils
import waf_evasion
from rich.panel import Panel
from vulnmap_utils import WafHealthMonitor, WafStatus

def _orchestrate_sqlmap(targets: List[str], waf_monitor: WafHealthMonitor) -> List[Dict[str, Any]]:
    """Orkiestruje skanowanie za pomocą SQLMap, reagując na stan WAF."""
    utils.log_and_echo("Rozpoczynam skanowanie SQL Injection za pomocą SQLMap...", "INFO")
    findings = []
    
    for url in targets:
        # --- KRYTYCZNY PUNKT KONTROLNY ---
        status = waf_monitor.get_status()
        if status == WafStatus.RED:
            utils.log_and_echo("WAF ZABLOKOWANY! Wstrzymuję SQLMap i czekam na zielone światło.", "ERROR")
            # TODO: Dodać logikę czekania na zmianę statusu
            continue # Pomiń ten cel na razie
        
        if status == WafStatus.YELLOW:
            utils.log_and_echo("WAF PODEJRZANY. Zwalniam skanowanie SQLMap.", "WARN")
            time.sleep(10)
            
        command = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1"]
        
        if config.SAFE_MODE:
            tamper_scripts = waf_evasion.select_sqlmap_tamper_scripts()
            if tamper_scripts:
                command.append(f"--tamper={','.join(tamper_scripts)}")
            command.append("--random-agent")
            command.append("--delay=1")

        utils.log_and_echo(f"Uruchamiam SQLMap dla: {url}", "DEBUG")
        # TODO: Zaimplementować uruchomienie procesu i parsowanie wyników
        # process = subprocess.run(...)
        # parsed_findings = _parse_sqlmap_output(...)
        # findings.extend(parsed_findings)
        
    return findings

def start_active_scan(categorized_targets: Dict[str, Any], waf_monitor: WafHealthMonitor) -> List[Dict[str, Any]]:
    """
    Punkt wejściowy dla Fazy 2. Uruchamia aktywne skanery aplikacji webowych.
    Zwraca listę znalezionych podatności.
    """
    utils.console.print(Panel("[bold cyan]Rozpoczynam Fazę 2: Aktywne Skanowanie Aplikacji Webowych[/bold cyan]"))
    all_findings = []
    
    urls_with_params = categorized_targets.get("urls_with_params", [])
    if not urls_with_params:
        utils.log_and_echo("Brak URLi z parametrami do aktywnego skanowania w Fazie 2.", "WARN")
        return []
        
    # --- Skanowanie SQL Injection ---
    sql_findings = _orchestrate_sqlmap(urls_with_params, waf_monitor)
    all_findings.extend(sql_findings)
    utils.console.print(f"[yellow]Skanowanie SQLMap jest w budowie. Pomijam.[/yellow]")
    
    # --- Skanowanie XSS (np. Dalfox) ---
    # xss_findings = _orchestrate_dalfox(urls_with_params, waf_monitor)
    # all_findings.extend(xss_findings)
    utils.console.print(f"[yellow]Skanowanie XSS (Dalfox) jest w budowie. Pomijam.[/yellow]")
    
    # --- Skanowanie CMS (np. WPScan) ---
    # cms_findings = _orchestrate_cms_scans(...)
    # all_findings.extend(cms_findings)
    utils.console.print(f"[yellow]Skanowanie CMS jest w budowie. Pomijam.[/yellow]")
    
    utils.console.print(f"Faza 2 zakończona. Całkowita liczba znalezisk: [bold green]{len(all_findings)}[/bold green]")
    return all_findings
