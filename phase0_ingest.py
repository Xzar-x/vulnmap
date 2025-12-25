# /usr/local/share/vulnmap/phase0_ingest.py

import json
import subprocess
from typing import Any, Dict, List, Optional, Union

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
                "phase0_osint": { # Dostosowane do struktury widocznej w Twoim pliku
                    "ip": data.get("ip"),
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

def _extract_url_list(data: Any) -> List[str]:
    """Pomocnicza funkcja wyciągająca URLe z listy obiektów lub listy stringów."""
    urls = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and 'url' in item:
                urls.append(item['url'])
            elif isinstance(item, str):
                urls.append(item)
    return urls

def _categorize_assets(shadowmap_data: Dict[str, Any]) -> Dict[str, Any]:
    """Kategoryzuje zasoby z danych wejściowych na listy do dalszego skanowania."""
    utils.log_and_echo("Kategoryzuję zasoby do skanowania...", "INFO")
    
    # 1. Pobieranie Technologii (Obsługa różnych struktur JSON)
    technologies = []
    # Sprawdź 'phase0_osint' (root)
    if "phase0_osint" in shadowmap_data:
        technologies = shadowmap_data["phase0_osint"].get("technologies", [])
    # Sprawdź 'target_info' (alternatywa)
    elif "target_info" in shadowmap_data:
        technologies = shadowmap_data["target_info"].get("technologies", [])
    
    categorized = {
        "root_urls": set(),
        "urls_with_params": set(),
        "js_files": set(),
        "api_endpoints": set(),
        "hosts_with_ports": {},
        "technologies": set(technologies)
    }

    # 2. Pobieranie URLi - Logika "Hybrydowa" (szukamy w root i w results)
    raw_active_urls = []
    raw_dirsearch_urls = []
    raw_crawl_urls = []

    # A. Sprawdź strukturę zagnieżdżoną w "results" (klasyczny ShadowMap)
    results_node = shadowmap_data.get("results", {})
    if results_node:
        raw_active_urls.extend(results_node.get("phase1_subdomains", {}).get("active_urls", []))
        raw_dirsearch_urls.extend(results_node.get("phase3_directories", {}).get("verified_urls", []))
        raw_crawl_urls.extend(results_node.get("phase4_webcrawling", {}).get("all_urls", []))

    # B. Sprawdź strukturę płaską (alternatywne formaty JSON lub customowe raporty)
    # Czasami klucze są bezpośrednio w roocie
    if "phase1_active_urls" in shadowmap_data:
        raw_active_urls.extend(shadowmap_data["phase1_active_urls"])
    if "phase1_subdomains" in shadowmap_data: # Inny wariant
         data_p1 = shadowmap_data["phase1_subdomains"]
         if isinstance(data_p1, dict):
             raw_active_urls.extend(data_p1.get("active_urls", []))
    
    if "phase3_verified_urls" in shadowmap_data:
        raw_dirsearch_urls.extend(shadowmap_data["phase3_verified_urls"])
        
    if "phase4_webcrawling" in shadowmap_data:
        data_p4 = shadowmap_data["phase4_webcrawling"]
        if isinstance(data_p4, list): # Czasami to lista URLi
             raw_crawl_urls.extend(data_p4)
        elif isinstance(data_p4, dict): # Czasami słownik
             raw_crawl_urls.extend(data_p4.get("all_urls", []))

    # Normalizacja danych (wyciągnij stringi URL z obiektów lub list)
    all_urls_flat = _extract_url_list(raw_active_urls) + \
                    _extract_url_list(raw_dirsearch_urls) + \
                    _extract_url_list(raw_crawl_urls)

    # Jeśli lista jest nadal pusta, spróbuj znaleźć cokolwiek co wygląda na URL w 'results'
    if not all_urls_flat and results_node:
         # Desperacka próba iteracji
         for key, val in results_node.items():
             if isinstance(val, dict) and "url" in val:
                 all_urls_flat.append(val["url"])
             elif isinstance(val, list):
                 all_urls_flat.extend(_extract_url_list(val))

    for url_str in all_urls_flat:
        if not url_str or not isinstance(url_str, str): continue
        
        # Dodaj "root" url (np. https://example.com)
        try:
            parts = url_str.split("/")
            if len(parts) >= 3:
                base_url = "/".join(parts[:3])
                categorized["root_urls"].add(base_url)
        except Exception:
            pass

        if "?" in url_str and "=" in url_str:
            categorized["urls_with_params"].add(url_str)
        if url_str.endswith(".js"):
            categorized["js_files"].add(url_str)
        if any(keyword in url_str.lower() for keyword in ["api/", "/api.", "graphql"]):
             categorized["api_endpoints"].add(url_str)

    # 3. Kategoryzacja portów
    # Sprawdź target_info lub phase2_portscan
    hosts_ports = {}
    if "phase2_portscan" in shadowmap_data:
        # Obsługa formatu gdzie kluczem jest IP
        p2_data = shadowmap_data["phase2_portscan"]
        if isinstance(p2_data, dict):
            hosts_ports = p2_data
    elif "results" in shadowmap_data:
        hosts_ports = shadowmap_data["results"].get("phase2_portscan", {})
    
    # Fallback do target_info
    if not hosts_ports:
        target_info = shadowmap_data.get("target_info", {})
        if "open_ports" in target_info:
            hosts_ports = target_info["open_ports"]

    categorized["hosts_with_ports"] = hosts_ports

    # Konwersja setów na listy i sortowanie
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
    
    result = _categorize_assets(shadowmap_data)
    
    # Szybka walidacja - jeśli pusty wynik, ostrzeż użytkownika wyraźniej
    if not result["root_urls"] and not result["hosts_with_ports"]:
         utils.console.print("[bold red]OSTRZEŻENIE: Nie znaleziono żadnych URLi ani portów w pliku wejściowym![/bold red]")
         utils.console.print("Sprawdź strukturę pliku JSON lub czy skan ShadowMap coś wykrył.")
    
    return result