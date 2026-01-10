#!/usr/bin/env python3

import datetime
import json
import os
import re
import sys
import tty
import termios
import webbrowser
import time
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
    print(f"BŁĄD: Nie można zaimportować modułów. Uruchom install.py lub upewnij się, że jesteś w dobrym katalogu. Błąd: {e}")
    sys.exit(1)

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="VulnMap: Zautomatyzowany, kontekstowy skaner podatności.",
)


def get_key() -> str:
    """Pobiera pojedynczy znak z klawiatury bez konieczności wciskania Enter (Linux/Unix)."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    except KeyboardInterrupt:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        raise KeyboardInterrupt
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


def get_single_char_input_with_prompt(prompt_text: Text) -> str:
    """Wyświetla wyśrodkowany prompt i pobiera jeden znak (styl ShadowMap)."""
    utils.console.print(Align.center(prompt_text), end="")
    sys.stdout.flush()
    try:
        choice = get_key()
    except KeyboardInterrupt:
        return "\x03"  # Ctrl+C code
        
    utils.console.print(f" [bold cyan]{choice}[/bold cyan]")
    time.sleep(0.2) # Krótkie opóźnienie dla UX
    return choice


def display_banner():
    utils.console.clear()
    f = Figlet(font="slant")
    banner_text = f.renderText("VulnMap")
    # Styl spójny z ShadowMap: Cyan Title
    utils.console.print(Align.center(Text(banner_text, style="bold cyan")))
    # Styl spójny z ShadowMap: Yellow Subtitle
    utils.console.print(
        Align.center(
            "--- Automated Context-Aware Vulnerability Scanner ---", style="bold yellow"
        )
    )
    utils.console.print(Align.center("[dim white]Made by Xzar & Gemini[/dim white]\n"))


def show_settings_menu():
    """Menu ustawień wywoływane klawiszem 's'."""
    while True:
        utils.console.clear()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Skanowania[/bold cyan]"))
        )

        mode_color = "green" if config.SAFE_MODE else "red"
        mode_text = "WŁĄCZONY" if config.SAFE_MODE else "WYŁĄCZONY"

        table = Table(show_header=False, box=None)
        table.add_row(
            "[bold cyan][1][/bold cyan]",
            f"Tryb Bezpieczny (Safe Mode): [bold {mode_color}]{mode_text}[/bold {mode_color}]",
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]",
            f"Liczba wątków (Nuclei): [bold yellow]{config.NUCLEI_RATE_LIMIT_SAFE if config.SAFE_MODE else config.NUCLEI_RATE_LIMIT}[/bold yellow]",
        )
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wróć do menu głównego")

        utils.console.print(Align.center(table))
        
        prompt = Text.from_markup("\n[bold cyan]Wybierz opcję[/bold cyan]", justify="center")
        try:
            key = get_single_char_input_with_prompt(prompt).lower()
        except KeyboardInterrupt:
            break

        if key == "1":
            config.SAFE_MODE = not config.SAFE_MODE
            if config.SAFE_MODE:
                utils.log_and_echo("Przełączono na TRYB BEZPIECZNY (Stealth).", "WARN")
            else:
                utils.log_and_echo("Przełączono na TRYB NORMALNY.", "WARN")
            time.sleep(1)

        elif key == "2":
            if config.NUCLEI_RATE_LIMIT > 50:
                config.NUCLEI_RATE_LIMIT = 25
            else:
                config.NUCLEI_RATE_LIMIT += 25
            utils.log_and_echo(
                f"Zmieniono rate-limit na: {config.NUCLEI_RATE_LIMIT}", "INFO"
            )
            time.sleep(0.5)

        elif key == "q" or key == "\x1b":  # ESC lub q
            break


def display_main_menu() -> str:
    """Wyświetla główne menu w stylu ShadowMap i zwraca wybór użytkownika."""
    display_banner()
    
    # Panel Menu Głównego
    utils.console.print(
        Align.center(Panel.fit("[bold cyan]VulnMap Main Menu[/bold cyan]"))
    )
    
    # Wyświetlanie celu
    utils.console.print(
        Align.center(f"\nObecny cel: [bold green]{config.TARGET_INPUT}[/bold green]\n")
    )

    # Pasek informacyjny o ustawieniach (jak w ShadowMap)
    settings_info = []
    if config.SAFE_MODE:
        settings_info.append("[green]Safe Mode: ON[/green]")
    else:
        settings_info.append("[red]Safe Mode: OFF[/red]")
    
    nuclei_limit = config.NUCLEI_RATE_LIMIT_SAFE if config.SAFE_MODE else config.NUCLEI_RATE_LIMIT
    settings_info.append(f"Nuclei Threads: {nuclei_limit}")
    
    if settings_info:
        utils.console.print(Align.center(f"[dim]{' | '.join(settings_info)}[/dim]"))

    # Tabela opcji
    table = Table(show_header=False, show_edge=False, padding=(0, 2))
    table.add_row("[bold cyan][1][/bold cyan]", "Faza 1: Skanowanie Pasywne")
    table.add_row("[bold cyan][2][/bold cyan]", "Faza 2: Aktywne Skanowanie Aplikacji")
    table.add_row("[bold cyan][3][/bold cyan]", "Faza 3: Skanowanie Infrastruktury")
    table.add_row("[bold cyan][\fa][/bold cyan]", "Uruchom wszystkie fazy po kolei")
    table.add_section()
    table.add_row("[bold cyan][\fs][/bold cyan]", "Ustawienia skanowania")
    table.add_row("[bold cyan][\fq][/bold cyan]", "Zapisz raporty i Wyjdź")

    utils.console.print(Align.center(table))
    
    # Prompt w stylu ShadowMap
    prompt = Text.from_markup("\n[bold cyan]Wybierz fazę[/bold cyan]", justify="center")
    return get_single_char_input_with_prompt(prompt)


def _generate_summary_txt(all_findings: List[Dict[str, Any]]):
    """Generuje plik wyniki.txt z promptem dla AI."""
    utils.log_and_echo("Generuję podsumowanie tekstowe dla AI (wyniki.txt)...", "INFO")

    min_severity_level = config.SEVERITY_ORDER.get(
        config.AI_SUMMARY_MIN_SEVERITY.lower(), 99
    )

    # Filtrowanie i sortowanie
    filtered_findings = sorted(
        [
            f
            for f in all_findings
            if config.SEVERITY_ORDER.get(f.get("severity", "info").lower(), 99)
            <= min_severity_level
        ],
        key=lambda f: config.SEVERITY_ORDER.get(f.get("severity", "info").lower(), 99),
    )

    if not filtered_findings:
        utils.log_and_echo(
            f"Brak znalezisk o poziomie {config.AI_SUMMARY_MIN_SEVERITY} lub wyższym. Generuję pusty raport AI.",
            "WARN",
        )
        findings_content = "BRAK KRYTYCZNYCH PODATNOŚCI WYMAGAJĄCYCH ANALIZY AI."
    else:
        findings_text_parts = []
        for f in filtered_findings:
            details = f.get("details", "Brak")
            # Konwersja detali do stringa jeśli to obiekt
            if isinstance(details, (dict, list)):
                try:
                    details = json.dumps(details, ensure_ascii=False)
                except:
                    details = str(details)

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

    final_content = config.AI_PROMPT_TEMPLATE.format(
        target=config.TARGET_INPUT,
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        min_severity=config.AI_SUMMARY_MIN_SEVERITY.upper(),
        findings=findings_content,
    )

    try:
        report_path = os.path.join(config.REPORT_DIR, "wyniki.txt")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(final_content)
        utils.log_and_echo(f"Pomyślnie zapisano podsumowanie AI: {report_path}", "INFO")
    except Exception as e:
        utils.log_and_echo(f"Błąd podczas zapisu pliku wyniki.txt: {e}", "ERROR")


def _generate_html_report(all_findings: List[Dict[str, Any]]):
    """Generuje raport HTML i otwiera go w przeglądarce."""
    utils.log_and_echo("Generuję interaktywny raport HTML...", "INFO")

    # 1. Znajdowanie szablonu (Fallback logic)
    template_path = config.HTML_TEMPLATE_PATH
    
    if not os.path.exists(template_path):
        local_path = os.path.join(os.getcwd(), "vulnmap_report_template.html")
        script_dir_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnmap_report_template.html")
        
        if os.path.exists(local_path):
            template_path = local_path
        elif os.path.exists(script_dir_path):
            template_path = script_dir_path
        else:
            utils.log_and_echo(
                f"BŁĄD KRYTYCZNY: Nie znaleziono szablonu HTML w {config.HTML_TEMPLATE_PATH} ani w katalogu bieżącym!",
                "ERROR",
            )
            return

    try:
        # Wczytanie szablonu
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()

        # Przygotowanie danych
        json_data = json.dumps(all_findings, indent=2, ensure_ascii=False)
        current_year = str(datetime.datetime.now().year)

        # Podmiana placeholderów
        html_content = template_content.replace("{{TARGET_INPUT}}", config.TARGET_INPUT)
        html_content = html_content.replace("{{CURRENT_YEAR}}", current_year)
        html_content = html_content.replace("{{VULN_DATA_JSON}}", json_data)

        # Zapis raportu
        report_path = os.path.join(config.REPORT_DIR, "report.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        utils.console.print(
            f"[bold green]Raport HTML zapisano w: {report_path}[/bold green]"
        )

        # Auto-Open
        utils.log_and_echo("Otwieram raport w domyślnej przeglądarce...", "INFO")
        try:
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
        except Exception as e:
            utils.log_and_echo(
                f"Nie udało się otworzyć przeglądarki automatycznie: {e}", "WARN"
            )

    except Exception as e:
        utils.log_and_echo(f"Krytyczny błąd podczas generowania HTML: {e}", "ERROR")


def generate_reports(all_findings: List[Dict[str, Any]]):
    """Orkiestruje generowanie raportów."""

    # Nawet jeśli lista pusta, generujemy raport z informacją "Brak danych"
    if not all_findings:
        utils.console.print(
            "[yellow]Brak znalezionych podatności. Generuję puste raporty.[/yellow]"
        )

    utils.console.print(
        Align.center(Panel.fit("[bold blue]Zapisywanie wyników...[/bold blue]"))
    )

    # 1. Raport TXT (dla AI)
    _generate_summary_txt(all_findings)

    # 2. Raport HTML (dla Człowieka) + Auto Open
    _generate_html_report(all_findings)


@app.command()
def main(
    target: Optional[str] = typer.Argument(
        None, help="Cel skanowania: URL, domena lub adres IP."
    ),
    input_file: Optional[str] = typer.Option(
        None, "-i", "--input", help="Plik wejściowy, np. report.json z ShadowMap."
    ),
    output_dir: str = typer.Option(".", "-o", "--output-dir", help="Katalog raportów."),
    safe_mode: bool = typer.Option(
        False, "--safe-mode", help="Włącz tryb bezpieczny (wolniejszy)."
    ),
):
    if not target and not input_file:
        utils.console.print(
            "[red]Błąd: Musisz podać cel lub plik wejściowy (--input).[/red]"
        )
        raise typer.Exit()

    config.SAFE_MODE = safe_mode
    config.TARGET_INPUT = target or input_file

    report_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_target = re.sub(
        r"[^a-zA-Z0-9.-]", "_", config.TARGET_INPUT.split("/")[-1]
    )
    config.REPORT_DIR = os.path.join(
        output_dir, f"vulnmap_{sanitized_target}_{report_time}"
    )
    os.makedirs(config.REPORT_DIR, exist_ok=True)

    # Inicjalizacja Fazy 0
    display_banner()
    utils.console.print(
        f"Cel: [bold green]{config.TARGET_INPUT}[/bold green], Raporty w: [bold cyan]{config.REPORT_DIR}[/bold cyan]"
    )

    all_findings: List[Dict[str, Any]] = []

    utils.console.print(
        Align.center(
            Panel.fit(
                "[bold cyan]Faza 0: Przetwarzanie i kategoryzacja celów...[/bold cyan]"
            )
        )
    )
    categorized_targets = phase0_ingest.start_ingest(target, input_file)
    if not categorized_targets:
        utils.console.print("[red]Nie udało się przetworzyć celów. Zakończono.[/red]")
        raise typer.Exit()

    # --- INICJALIZACJA WAF MONITOR ---
    waf_monitor = utils.WafHealthMonitor(categorized_targets.get("root_urls", []))
    waf_monitor.start()

    try:
        while True:
            choice = display_main_menu().lower()
            
            # Obsługa wyjścia awaryjnego z prompta
            if choice == "\x03": # Ctrl+C
                 raise KeyboardInterrupt

            if choice == "1":
                phase1_findings = phase1_passive.start_passive_scan(categorized_targets)
                all_findings.extend(phase1_findings)
                utils.console.print(
                    Align.center("[bold green]Faza 1 zakończona. Naciśnij dowolny klawisz...[/bold green]")
                )
                get_key()

            elif choice == "2":
                phase2_findings = phase2_active_app.start_active_scan(
                    categorized_targets, waf_monitor
                )
                all_findings.extend(phase2_findings)
                utils.console.print(
                    Align.center("[bold green]Faza 2 zakończona. Naciśnij dowolny klawisz...[/bold green]")
                )
                get_key()

            elif choice == "3":
                phase3_findings = phase3_infra.start_infra_scan(categorized_targets)
                all_findings.extend(phase3_findings)
                utils.console.print(
                    Align.center("[bold green]Faza 3 zakończona. Naciśnij dowolny klawisz...[/bold green]")
                )
                get_key()

            elif choice == "a":
                utils.console.print(
                    Align.center(
                        Panel.fit(
                            "[bold magenta]URUCHAMIAM PEŁNĄ AUTOMATYZACJĘ (Faza 1 -> 2 -> 3)[/bold magenta]"
                        )
                    )
                )

                # Faza 1
                utils.log_and_echo(">>> AUTO: Start Fazy 1", "INFO")
                p1 = phase1_passive.start_passive_scan(categorized_targets)
                all_findings.extend(p1)

                # Faza 2
                utils.log_and_echo(">>> AUTO: Start Fazy 2", "INFO")
                p2 = phase2_active_app.start_active_scan(
                    categorized_targets, waf_monitor
                )
                all_findings.extend(p2)

                # Faza 3
                utils.log_and_echo(">>> AUTO: Start Fazy 3", "INFO")
                p3 = phase3_infra.start_infra_scan(categorized_targets)
                all_findings.extend(p3)

                utils.console.print(
                    Align.center(
                        Panel.fit("[bold green]AUTOMATYZACJA ZAKOŃCZONA![/bold green]")
                    )
                )
                
                # AUTOMATYCZNY ZAPIS RAPORTÓW PO SKOŃCZONEJ PRACY
                utils.log_and_echo("Zapisuję wyniki automatycznie...", "INFO")
                generate_reports(all_findings)
                
                utils.console.print(
                    Align.center("[dim]Naciśnij dowolny klawisz, aby wrócić do menu...[/dim]")
                )
                get_key()

            elif choice == "s":
                show_settings_menu()

            elif choice == "q" or choice == "\x1b":  # q lub ESC
                generate_reports(all_findings)
                break

            # Brak 'else' - ignorujemy inne klawisze
    except KeyboardInterrupt:
        # Globalny catch dla Ctrl+C podczas działania skanerów
        utils.console.print("\n[bold red]PRZERWANO PRZEZ UŻYTKOWNIKA![/bold red]")
        if all_findings:
             if typer.confirm("Czy zapisać dotychczasowe znaleziska?"):
                 generate_reports(all_findings)
    finally:
        waf_monitor.stop()


if __name__ == "__main__":
    app()
