#!/usr/bin/env python3

import datetime
import json
import os
import sys
from typing import Any, Dict, Optional

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
    # W przyszłości importy modułów faz
    # import phase0_ingest
    # import phase1_passive
    # ...
except ImportError as e:
    print(f"BŁĄD: Nie można zaimportować modułów. Uruchom install.py. Błąd: {e}")
    sys.exit(1)

# --- Definicja aplikacji Typer ---
app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="""
    VulnMap: Zautomatyzowany, kontekstowy skaner podatności.

    Narzędzie przeprowadza skanowanie w wielu fazach:
    - Faza 0: Przetwarzanie i kategoryzacja celów
    - Faza 1: Skanowanie pasywne i konfiguracyjne
    - Faza 2: Aktywne, ukierunkowane skanowanie aplikacji
    - Faza 3: Skanowanie podatności w infrastrukturze
    """,
)

def display_banner():
    """Wyświetla baner VulnMap."""
    f = Figlet(font="slant")
    banner_text = f.renderText("VulnMap")
    utils.console.print(Align.center(Text(banner_text, style="bold magenta")))
    utils.console.print(
        Align.center("--- Automated Context-Aware Vulnerability Scanner ---", style="bold yellow")
    )
    utils.console.print(Align.center("[dim white]Made by Xzar & Gemini[/dim white]\n"))

def display_main_menu():
    """Wyświetla główne menu wyboru faz skanowania."""
    utils.console.clear()
    display_banner()
    utils.console.print(Align.center(Panel.fit("[bold magenta]VulnMap Main Menu[/bold magenta]")))
    utils.console.print(
        Align.center(f"\nObecny cel: [bold green]{config.TARGET_INPUT}[/bold green]\n")
    )

    table = Table(show_header=False, show_edge=False, padding=(0, 2))
    table.add_row("[bold cyan][1][/bold cyan]", "Faza 1: Skanowanie Pasywne i Konfiguracyjne")
    table.add_row("[bold cyan][2][/bold cyan]", "Faza 2: Aktywne Skanowanie Aplikacji Webowych")
    table.add_row("[bold cyan][3][/bold cyan]", "Faza 3: Skanowanie Infrastruktury")
    table.add_row("[bold cyan][a][/bold cyan]", "Uruchom wszystkie fazy po kolei")
    table.add_section()
    table.add_row("[bold cyan][s][/bold cyan]", "Ustawienia skanowania")
    table.add_row("[bold cyan][\fq][/bold cyan]", "Zapisz raporty i Wyjdź")
    utils.console.print(Align.center(table))
    
    # Ta funkcja nie istnieje w utils, trzeba by ją przenieść z shadowmap lub zduplikować
    # return utils.get_single_char_input_with_prompt(...)
    choice = input("Wybierz opcję: ")
    return choice


def generate_reports(scan_results: Dict[str, Any]):
    """Orkiestruje generowanie wszystkich formatów raportów."""
    utils.console.print(Align.center(Panel.fit("[bold blue]Generowanie raportów...[/bold blue]")))
    # TODO: Zaimplementować generowanie raportów
    # _generate_json_report(scan_results)
    # _generate_html_report(scan_results)
    print("Funkcjonalność generowania raportów jest w budowie.")

@app.command()
def main(
    target: Optional[str] = typer.Argument(
        None, help="Cel skanowania: URL, domena lub adres IP."
    ),
    input_file: Optional[str] = typer.Option(
        None, "-i", "--input", help="Plik wejściowy, np. report.json z ShadowMap.",
        rich_help_panel="Input"
    ),
    output_dir: str = typer.Option(
        ".", "-o", "--output-dir", help="Katalog, w którym zostaną zapisane raporty.",
        rich_help_panel="Output"
    ),
    safe_mode: bool = typer.Option(
        False, "--safe-mode", help="Włącz tryb bezpieczny (wolniejsze, cichsze skanowanie w celu unikania WAF).",
        rich_help_panel="Tuning"
    ),
):
    """Główna funkcja programu VulnMap."""
    if not target and not input_file:
        utils.console.print("[red]Błąd: Musisz podać cel lub plik wejściowy (--input).[/red]")
        raise typer.Exit()
    
    # --- Inicjalizacja konfiguracji ---
    config.SAFE_MODE = safe_mode
    config.TARGET_INPUT = target or input_file
    
    # TODO: Ustawienie katalogu raportów
    
    display_banner()
    utils.console.print(f"Cel: [bold green]{config.TARGET_INPUT}[/bold green]")
    utils.console.print(f"Tryb bezpieczny: {'[green]Włączony[/green]' if config.SAFE_MODE else '[red]Wyłączony[/red]'}")
    
    # --- FAZA 0: Przetwarzanie celów ---
    utils.console.print(Align.center(Panel.fit("[bold cyan]Faza 0: Przetwarzanie i kategoryzacja celów...[/bold cyan]")))
    # categorized_targets = phase0_ingest.start(target, input_file)
    utils.console.print("[yellow]Faza 0 (Ingest) jest w budowie.[/yellow]")

    # --- Główna pętla menu ---
    scan_results = {} # Pusty słownik na zagregowane wyniki
    while True:
        choice = display_main_menu()
        
        if choice == '1':
            utils.console.print("[yellow]Faza 1 (Pasywna) jest w budowie.[/yellow]")
        elif choice == '2':
            utils.console.print("[yellow]Faza 2 (Aktywna) jest w budowie.[/yellow]")
        elif choice == '3':
            utils.console.print("[yellow]Faza 3 (Infrastruktura) jest w budowie.[/yellow]")
        elif choice.lower() == 'a':
            utils.console.print("[yellow]Skanowanie wszystkich faz jest w budowie.[/yellow]")
        elif choice.lower() == 's':
            utils.console.print("[yellow]Menu ustawień jest w budowie.[/yellow]")
        elif choice.lower() == 'q':
            generate_reports(scan_results)
            break
        else:
            utils.console.print("[red]Nieprawidłowa opcja.[/red]")
        
        input("\nNaciśnij Enter, aby wrócić do menu...")

if __name__ == "__main__":
    app()
