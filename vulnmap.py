#!/usr/bin/env python3

import datetime
import json
import os
import sys
from typing import Any, Dict, List, Optional

import typer
from pyfiglet import Figlet
from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# --- Dodanie ścieżki i import modułów ---
SHARE_DIR = "/usr/local/share/vulnmap/"
if SHARE_DIR not in sys.path:
    sys.path.insert(0, SHARE_DIR)

try:
    import vulnmap_config as config
    import vulnmap_utils as utils
    import phase0_ingest
    import phase1_passive
    import phase2_active_app
    import phase3_infra
except ImportError as e:
    print(f"BŁĄD: Nie można zaimportować modułów. Uruchom install.py. Błąd: {e}")
    sys.exit(1)

app = typer.Typer(
    add_completion=False, rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="VulnMap: Zautomatyzowany, kontekstowy skaner podatności."
)

def display_banner():
    f = Figlet(font="slant")
    banner_text = f.renderText("VulnMap")
    utils.console.print(Align.center(Text(banner_text, style="bold magenta")))
    utils.console.print(Align.center("--- Automated Context-Aware Vulnerability Scanner ---", style="bold yellow"))
    utils.console.print(Align.center("[dim white]Made by Xzar & Gemini[/dim white]\n"))

def display_main_menu():
    utils.console.clear(); display_banner()
    utils.console.print(Align.center(Panel.fit("[bold magenta]VulnMap Main Menu[/bold magenta]")))
    utils.console.print(Align.center(f"\nObecny cel: [bold green]{config.TARGET_INPUT}[/bold green]\n"))
    table = Table(show_header=False, show_edge=False, padding=(0, 2))
    table.add_row("[bold cyan][1][/bold cyan]", "Faza 1: Skanowanie Pasywne i Konfiguracyjne")
    table.add_row("[bold cyan][2][/bold cyan]", "Faza 2: Aktywne Skanowanie Aplikacji Webowych")
    table.add_row("[bold cyan][3][/bold cyan]", "Faza 3: Skanowanie Infrastruktury")
    table.add_row("[bold cyan][a][/bold cyan]", "Uruchom wszystkie fazy po kolei")
    table.add_section()
    table.add_row("[bold cyan][s][/bold cyan]", "Ustawienia skanowania")
    table.add_row("[bold cyan][\fq][/bold cyan]", "Zapisz raporty i Wyjdź")
    utils.console.print(Align.center(table))
    choice = input("Wybierz opcję: ")
    return choice

# NOWOŚĆ: Funkcja generująca podsumowanie dla AI
def _generate_summary_txt(all_findings: List[Dict[str, Any]]):
    """Generuje plik wyniki.txt z promptem i przefiltrowanymi wynikami dla AI."""
    utils.log_and_echo("Generuję podsumowanie tekstowe dla AI (wyniki.txt)...", "INFO")

    min_severity_level = config.SEVERITY_ORDER.get(config.AI_SUMMARY_MIN_SEVERITY.lower(), 99)

    # Filtrowanie i sortowanie podatności
    filtered_findings = sorted(
        [f for f in all_findings if config.SEVERITY_ORDER.get(f.get("severity", "info").lower(), 99) <= min_severity_level],
        key=lambda f: config.SEVERITY_ORDER.get(f.get("severity", "info").lower(), 99)
    )

    if not filtered_findings:
        utils.log_and_echo("Brak wystarczająco istotnych wyników do wygenerowania podsumowania AI.", "WARN")
        return

    # Formatowanie każdego znaleziska do postaci tekstowej
    findings_text_parts = []
    for f in filtered_findings:
        details = f.get('details', 'Brak')
        if isinstance(details, (dict, list)):
            details = json.dumps(details)

        finding_str = (
            f"--- ZNALEZISKO ---\n"
            f"Narzędzie: {f.get('source', 'N/A')}\n"
            f"Cel: {f.get('target', 'N/A')}\n"
            f"Podatność: {f.get('vulnerability', 'N/A')}\n"
            f"Poziom: {f.get('severity', 'N/A').upper()}\n"
            f"Szczegóły/PoC: {details}\n"
            f"Rekomendacja: {f.get('remediation', 'N/A')}"
        )
        findings_text_parts.append(finding_str)
    
    findings_content = "\n\n".join(findings_text_parts)

    # Uzupełnienie głównego szablonu
    final_content = config.AI_PROMPT_TEMPLATE.format(
        target=config.TARGET_INPUT,
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        min_severity=config.AI_SUMMARY_MIN_SEVERITY.upper(),
        findings=findings_content
    )

    try:
        report_path = os.path.join(config.REPORT_DIR, "wyniki.txt")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(final_content)
        utils.log_and_echo(f"Pomyślnie zapisano podsumowanie AI: {report_path}", "INFO")
    except Exception as e:
        utils.log_and_echo(f"Błąd podczas zapisu pliku wyniki.txt: {e}", "ERROR")


# ZMIANA: Funkcja `generate_reports` przyjmuje teraz `all_findings`
def generate_reports(all_findings: List[Dict[str, Any]]):
    """Orkiestruje generowanie wszystkich formatów raportów."""
    if not all_findings:
        utils.console.print("[yellow]Brak znalezionych podatności, nie generuję raportów.[/yellow]")
        return
        
    utils.console.print(Align.center(Panel.fit("[bold blue]Generowanie raportów...[/bold blue]")))
    
    # Wywołanie nowej funkcji
    _generate_summary_txt(all_findings)
    
    # TODO: Zaimplementować generowanie raportów JSON i HTML
    # _generate_json_report(all_findings)
    # _generate_html_report(all_findings)
    utils.console.print("[yellow]Generowanie raportów HTML i JSON jest w budowie.[/yellow]")

@app.command()
def main(
    target: Optional[str] = typer.Argument(None, help="Cel skanowania: URL, domena lub adres IP."),
    input_file: Optional[str] = typer.Option(None, "-i", "--input", help="Plik wejściowy, np. report.json z ShadowMap."),
    output_dir: str = typer.Option(".", "-o", "--output-dir", help="Katalog, w którym zostaną zapisane raporty."),
    safe_mode: bool = typer.Option(False, "--safe-mode", help="Włącz tryb bezpieczny."),
):
    if not target and not input_file:
        utils.console.print("[red]Błąd: Musisz podać cel lub plik wejściowy (--input).[/red]"); raise typer.Exit()
    
    config.SAFE_MODE = safe_mode
    config.TARGET_INPUT = target or input_file
    
    report_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    sanitized_target = re.sub(r'[^a-zA-Z0-9.-]', '_', config.TARGET_INPUT.split('/')[-1])
    config.REPORT_DIR = os.path.join(output_dir, f"vulnmap_{sanitized_target}_{report_time}")
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    
    display_banner()
    utils.console.print(f"Cel: [bold green]{config.TARGET_INPUT}[/bold green], Raporty w: [bold cyan]{config.REPORT_DIR}[/bold cyan]")
    utils.console.print(f"Tryb bezpieczny: {'[green]Włączony[/green]' if config.SAFE_MODE else '[red]Wyłączony[/red]'}")
    
    # ZMIANA: Inicjalizacja listy na wszystkie znaleziska
    all_findings: List[Dict[str, Any]] = []
    
    utils.console.print(Align.center(Panel.fit("[bold cyan]Faza 0: Przetwarzanie i kategoryzacja celów...[/bold cyan]")))
    categorized_targets = phase0_ingest.start_ingest(target, input_file)
    if not categorized_targets:
        utils.console.print("[red]Nie udało się przetworzyć celów. Zakończono.[/red]"); raise typer.Exit()

    # Inicjalizacja WAF Monitora
    # waf_monitor = utils.WafHealthMonitor(categorized_targets.get('root_urls', []))
    # waf_monitor.start()
    
    # --- Główna pętla menu ---
    while True:
        choice = display_main_menu()
        
        if choice == '1':
            phase1_findings = phase1_passive.start_passive_scan(categorized_targets)
            all_findings.extend(phase1_findings)
        elif choice == '2':
            # phase2_findings = phase2_active_app.start_active_scan(categorized_targets, waf_monitor)
            # all_findings.extend(phase2_findings)
            utils.console.print("[yellow]Faza 2 jest w budowie, dodaję przykładowe dane.[/yellow]")
            all_findings.append({"vulnerability": "SQL Injection", "severity": "critical", "target": "example.com/login", "details": "Found with SQLMap", "source": "SQLMap"})
        elif choice == '3':
            phase3_findings = phase3_infra.start_infra_scan(categorized_targets)
            all_findings.extend(phase3_findings)
        elif choice.lower() == 'a':
            utils.console.print("[yellow]Automatyczne skanowanie wszystkich faz jest w budowie.[/yellow]")
        elif choice.lower() == 's':
            utils.console.print("[yellow]Menu ustawień jest w budowie.[/yellow]")
        elif choice.lower() == 'q':
            # waf_monitor.stop()
            generate_reports(all_findings)
            break
        else:
            utils.console.print("[red]Nieprawidłowa opcja.[/red]")
        
        input("\nNaciśnij Enter, aby wrócić do menu...")

if __name__ == "__main__":
    app()
