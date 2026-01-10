#!/usr/bin/env python3

import datetime
import json
import os
import re
import sys
import tty
import termios
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
        # Przywrócenie ustawień terminala przed wyjściem
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        sys.exit(0)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


def display_banner():
    utils.console.clear()
    f = Figlet(font="slant")
    banner_text = f.renderText("VulnMap")
    utils.console.print(Align.center(Text(banner_text, style="bold magenta")))
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
            Align.center(Panel.fit("[bold blue]USTAWIENIA SKANOWANIA[/bold blue]"))
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
        table.add_row("[bold cyan][q][/bold cyan]", "Wróć do menu głównego")

        utils.console.print(Align.center(table))
        utils.console.print("\n[dim]Wybierz opcję (kliknij klawisz)...[/dim]")

        key = get_key().lower()

        if key == "1":
            config.SAFE_MODE = not config.SAFE_MODE
            # Aktualizacja zależnych zmiennych konfiguracyjnych w locie
            if config.SAFE_MODE:
                utils.log_and_echo("Przełączono na TRYB BEZPIECZNY (Stealth).", "WARN")
            else:
                utils.log_and_echo("Przełączono na TRYB NORMALNY.", "WARN")
            import time

            time.sleep(1)

        elif key == "2":
            if config.NUCLEI_RATE_LIMIT > 50:
                config.NUCLEI_RATE_LIMIT = 25
            else:
                config.NUCLEI_RATE_LIMIT += 25
            utils.log_and_echo(
                f"Zmieniono rate-limit na: {config.NUCLEI_RATE_LIMIT}", "INFO"
            )
            import time

            time.sleep(0.5)

        elif key == "q" or key == "\x1b":  # ESC lub q
            break


def display_main_menu_content():
    """Wyświetla treść menu głównego (bez czyszczenia i inputu)."""
    display_banner()
    utils.console.print(
        Align.center(f"\nObecny cel: [bold green]{config.TARGET_INPUT}[/bold green]\n")
    )

    table = Table(show_header=False, show_edge=False, padding=(0, 2))
    table.add_row("[bold cyan][1][/bold cyan]", "Faza 1: Skanowanie Pasywne")
    table.add_row("[bold cyan][2][/bold cyan]", "Faza 2: Aktywne Skanowanie Aplikacji")
    table.add_row("[bold cyan][3][/bold cyan]", "Faza 3: Skanowanie Infrastruktury")
    table.add_row(
        "[bold cyan][\fa][/bold cyan]", "Uruchom wszystkie fazy po kolei"
    )  # Przywrócono
    table.add_section()
    table.add_row("[bold cyan][\fs][/bold cyan]", "Ustawienia skanowania")
    table.add_row("[bold cyan][\fq][/bold cyan]", "Zapisz raporty i Wyjdź")

    utils.console.print(Align.center(table))
    utils.console.print(Align.center("\n[dim]Wybierz opcję (kliknij klawisz)...[/dim]"))


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
            "Brak wystarczająco istotnych wyników do wygenerowania podsumowania AI.",
            "WARN",
        )
        return

    findings_text_parts = []
    for f in filtered_findings:
        details = f.get("details", "Brak")
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


def generate_reports(all_findings: List[Dict[str, Any]]):
    """Orkiestruje generowanie raportów."""
    if not all_findings:
        utils.console.print(
            "[yellow]Brak znalezionych podatności, nie generuję raportów.[/yellow]"
        )
        return

    utils.console.print(
        Align.center(Panel.fit("[bold blue]Generowanie raportów...[/bold blue]"))
    )

    _generate_summary_txt(all_findings)
    utils.console.print(
        f"[green]Raport tekstowy dla AI zapisano w: {config.REPORT_DIR}/wyniki.txt[/green]"
    )


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
            display_main_menu_content()
            choice = get_key().lower()  # Instant action!

            if choice == "1":
                phase1_findings = phase1_passive.start_passive_scan(categorized_targets)
                all_findings.extend(phase1_findings)
                utils.console.print(
                    "[bold green]Faza 1 zakończona. Naciśnij dowolny klawisz...[/bold green]"
                )
                get_key()

            elif choice == "2":
                phase2_findings = phase2_active_app.start_active_scan(
                    categorized_targets, waf_monitor
                )
                all_findings.extend(phase2_findings)
                utils.console.print(
                    "[bold green]Faza 2 zakończona. Naciśnij dowolny klawisz...[/bold green]"
                )
                get_key()

            elif choice == "3":
                phase3_findings = phase3_infra.start_infra_scan(categorized_targets)
                all_findings.extend(phase3_findings)
                utils.console.print(
                    "[bold green]Faza 3 zakończona. Naciśnij dowolny klawisz...[/bold green]"
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
                utils.console.print(
                    "[dim]Naciśnij dowolny klawisz, aby wrócić do menu...[/dim]"
                )
                get_key()

            elif choice == "s":
                show_settings_menu()

            elif choice == "q" or choice == "\x1b":  # q lub ESC
                generate_reports(all_findings)
                break

            # Brak 'else' - ignorujemy inne klawisze
    finally:
        waf_monitor.stop()


if __name__ == "__main__":
    app()
#!/usr/bin/env python3

import datetime
import json
import os
import re
import sys
import tty
import termios
import webbrowser
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
        # Przywrócenie ustawień terminala przed wyjściem
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        sys.exit(0)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


def display_banner():
    utils.console.clear()
    f = Figlet(font="slant")
    banner_text = f.renderText("VulnMap")
    utils.console.print(Align.center(Text(banner_text, style="bold magenta")))
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
            Align.center(Panel.fit("[bold blue]USTAWIENIA SKANOWANIA[/bold blue]"))
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
        utils.console.print("\n[dim]Wybierz opcję (kliknij klawisz)...[/dim]")

        key = get_key().lower()

        if key == "1":
            config.SAFE_MODE = not config.SAFE_MODE
            # Aktualizacja zależnych zmiennych konfiguracyjnych w locie
            if config.SAFE_MODE:
                utils.log_and_echo("Przełączono na TRYB BEZPIECZNY (Stealth).", "WARN")
            else:
                utils.log_and_echo("Przełączono na TRYB NORMALNY.", "WARN")
            import time

            time.sleep(1)

        elif key == "2":
            if config.NUCLEI_RATE_LIMIT > 50:
                config.NUCLEI_RATE_LIMIT = 25
            else:
                config.NUCLEI_RATE_LIMIT += 25
            utils.log_and_echo(
                f"Zmieniono rate-limit na: {config.NUCLEI_RATE_LIMIT}", "INFO"
            )
            import time

            time.sleep(0.5)

        elif key == "q" or key == "\x1b":  # ESC lub q
            break


def display_main_menu_content():
    """Wyświetla treść menu głównego (bez czyszczenia i inputu)."""
    display_banner()
    utils.console.print(
        Align.center(f"\nObecny cel: [bold green]{config.TARGET_INPUT}[/bold green]\n")
    )

    table = Table(show_header=False, show_edge=False, padding=(0, 2))
    table.add_row("[bold cyan][1][/bold cyan]", "Faza 1: Skanowanie Pasywne")
    table.add_row("[bold cyan][2][/bold cyan]", "Faza 2: Aktywne Skanowanie Aplikacji")
    table.add_row("[bold cyan][3][/bold cyan]", "Faza 3: Skanowanie Infrastruktury")
    table.add_row("[bold cyan][a][/bold cyan]", "Uruchom wszystkie fazy po kolei")
    table.add_section()
    table.add_row("[bold cyan][s][/bold cyan]", "Ustawienia skanowania")
    table.add_row("[bold cyan][q][/bold cyan]", "Zapisz raporty i Wyjdź")

    utils.console.print(Align.center(table))
    utils.console.print(Align.center("\n[dim]Wybierz opcję (kliknij klawisz)...[/dim]"))


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
            f"Brak znalezisk o poziomie {config.AI_SUMMARY_MIN_SEVERITY} lub wyższym. Plik dla AI może być pusty.",
            "WARN",
        )
        # Mimo wszystko generujemy plik z informacją, że nic nie znaleziono
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

    # Sprawdzenie czy szablon istnieje
    if not os.path.exists(config.HTML_TEMPLATE_PATH):
        utils.log_and_echo(
            f"Błąd: Nie znaleziono szablonu HTML w {config.HTML_TEMPLATE_PATH}. Pomiń HTML.",
            "ERROR",
        )
        return

    try:
        # Wczytanie szablonu
        with open(config.HTML_TEMPLATE_PATH, "r", encoding="utf-8") as f:
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
            display_main_menu_content()
            choice = get_key().lower()  # Instant action!

            if choice == "1":
                phase1_findings = phase1_passive.start_passive_scan(categorized_targets)
                all_findings.extend(phase1_findings)
                utils.console.print(
                    "[bold green]Faza 1 zakończona. Naciśnij dowolny klawisz...[/bold green]"
                )
                get_key()

            elif choice == "2":
                phase2_findings = phase2_active_app.start_active_scan(
                    categorized_targets, waf_monitor
                )
                all_findings.extend(phase2_findings)
                utils.console.print(
                    "[bold green]Faza 2 zakończona. Naciśnij dowolny klawisz...[/bold green]"
                )
                get_key()

            elif choice == "3":
                phase3_findings = phase3_infra.start_infra_scan(categorized_targets)
                all_findings.extend(phase3_findings)
                utils.console.print(
                    "[bold green]Faza 3 zakończona. Naciśnij dowolny klawisz...[/bold green]"
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
                utils.console.print(
                    "[dim]Naciśnij dowolny klawisz, aby wrócić do menu...[/dim]"
                )
                get_key()

            elif choice == "s":
                show_settings_menu()

            elif choice == "q" or choice == "\x1b":  # q lub ESC
                # TUTAJ: Generowanie raportów i wyjście
                generate_reports(all_findings)
                break

            # Brak 'else' - ignorujemy inne klawisze
    finally:
        waf_monitor.stop()


if __name__ == "__main__":
    app()
