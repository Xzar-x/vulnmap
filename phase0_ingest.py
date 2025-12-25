# /usr/local/share/vulnmap/phase0_ingest.py

import json
import subprocess
from typing import Any, Dict, List, Optional

import vulnmap_config as config
import vulnmap_utils as utils
from rich.panel import Panel

def _run_httpx_mini_recon(target: str) -> Dict[str, Any]:
    """Uruchamia httpx w celu zebrania podstawowych informacji o pojedynczym celu."""
    utils.log_and_echo(f"Uruchamiam mini-rekonesans (httpx) dla celu: {target}", "INFO")
    results = {}
    try:
        command = ["httpx", "-u", target, "-silent", "-json", "-tech-detect", "-ip"]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if process.stdout:
            # Bierzemy ostatnią linię, na wypadek przekierowań http -> https
            last_line = process.stdout.strip().split("\n")[-1]
            data = json.loads(last_line)
            
            # Tworzymy strukturę podobną do raportu ShadowMap dla spójności
            results = {
                "scan_metadata": {"target": target},
                "target_info": {
                    "ip_address": data.get("ip"),
                    "technologies": data.get("tech", []),
                },
                "results": {
                    "phase1_subdomains": {
                        "active_urls": [{"url": data.get("url"), "status_code": data.get("status-code")}]
                    }
                }
            }
        else:
            utils.log_and_echo(f"Httpx nie zwrócił danych dla {target}", "WARN")

    except Exception as e:
        utils.log_and_echo(f"Błąd podczas mini-rekonesansu dla {target}: {e}", "ERROR")
    return results

def _categorize_assets(shadowmap_data: Dict[str, Any]) -> Dict[str, Any]:
    """Kategoryzuje zasoby z danych wejściowych na listy do dalszego skanowania."""
    utils.log_and_echo("Kategoryzuję zasoby do skanowania...", "INFO")
    
    categorized = {
        "root_urls": set(),
        "urls_with_params": set(),
        "js_files": set(),
        "api_endpoints": set(),
        "hosts_with_ports": {},
        "technologies": set(shadowmap_data.get("target_info", {}).get("technologies", []))
    }

    # Kategoryzacja URLi
    active_urls = shadowmap_data.get("results", {}).get("phase1_subdomains", {}).get("active_urls", [])
    dirsearch_urls = shadowmap_data.get("results", {}).get("phase3_directories", {}).get("verified_urls", [])
    crawl_urls = shadowmap_data.get("results", {}).get("phase4_webcrawling", {}).get("all_urls", [])
    
    all_urls_objects = active_urls + dirsearch_urls
    all_urls_flat = [item['url'] for item in all_urls_objects] + crawl_urls

    for url_str in all_urls_flat:
        # Dodaj "root" url (np. https://example.com)
        base_url = "/".join(url_str.split("/")[:3])
        categorized["root_urls"].add(base_url)

        if "?" in url_str and "=" in url_str:
            categorized["urls_with_params"].add(url_str)
        if url_str.endswith(".js"):
            categorized["js_files"].add(url_str)
        if any(keyword in url_str.lower() for keyword in ["api/", "/api.", "graphql"]):
             categorized["api_endpoints"].add(url_str)

    # Kategoryzacja portów
    categorized["hosts_with_ports"] = shadowmap_data.get("target_info", {}).get("open_ports", {})

    # Konwersja setów na listy
    for key in categorized:
        if isinstance(categorized[key], set):
            categorized[key] = sorted(list(categorized[key]))

    utils.console.print(Panel(
        f"[green]✓[/green] Root URLs: {len(categorized['root_urls'])}\n"
        f"[green]✓[/green] URLs z parametrami: {len(categorized['urls_with_params'])}\n"
        f"[green]✓[/green] Hosty z portami: {len(categorized['hosts_with_ports'])}\n"
        f"[green]✓[/green] Wykryte technologie: {len(categorized['technologies'])}",
        title="[bold cyan]Podsumowanie Kategoryzacji Zasobów[/bold cyan]",
        border_style="cyan"
    ))
    return categorized


def start_ingest(target: Optional[str], input_file: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Punkt wejściowy dla Fazy 0. Wczytuje i przetwarza dane wejściowe.
    Zwraca słownik ze skategoryzowanymi celami.
    """
    shadowmap_data = {}
    if input_file:
        utils.log_and_echo(f"Wczytuję dane z pliku wejściowego: {input_file}", "INFO")
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                shadowmap_data = json.load(f)
        except Exception as e:
            utils.log_and_echo(f"Nie udało się wczytać lub sparsować pliku JSON: {e}", "ERROR")
            return None
    elif target:
        utils.log_and_echo(f"Przetwarzam pojedynczy cel: {target}", "INFO")
        shadowmap_data = _run_httpx_mini_recon(target)
        if not shadowmap_data:
            utils.log_and_echo("Nie udało się zebrać podstawowych informacji o celu.", "ERROR")
            return None
    
    return _categorize_assets(shadowmap_data)
