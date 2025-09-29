#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys

try:
    import questionary
    from pyfiglet import Figlet
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("BŁĄD: Podstawowe pakiety (rich, questionary, pyfiglet) nie są zainstalowane.")
    print("Uruchom: pip3 install rich questionary pyfiglet typer")
    sys.exit(1)

console = Console(highlight=False)

# --- Definicje ---
BIN_DIR = "/usr/local/bin"
SHARE_DIR = "/usr/local/share/vulnmap"
ASSUME_YES = "-y" in sys.argv or "--yes" in sys.argv
DRY_RUN = "-d" in sys.argv or "--dry-run" in sys.argv
NONINTERACTIVE = "-n" in sys.argv or "--non-interactive" in sys.argv
IS_ROOT = os.geteuid() == 0

SYSTEM_DEPS = ["go", "python3", "pip3", "nmap", "sqlmap", "ruby", "gem", "git"]
GO_TOOLS = {
    "nuclei": "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
}
PYTHON_PKGS = ["rich", "questionary", "pyfiglet", "typer", "requests"]

# ZMIANA: Bardziej strukturalna definicja, aby wiedzieć co wymaga sudo
CUSTOM_INSTALLS = {
    "wpscan": {"command": "gem install wpscan", "needs_sudo": True},
    "testssl.sh": {"command": f"git clone --depth 1 https://github.com/drwetter/testssl.sh.git {os.path.join(SHARE_DIR, 'testssl.sh')}", "needs_sudo": True}
}

def display_banner():
    f = Figlet(font="slant")
    banner_text = f.renderText("VulnMap\nInstaller")
    console.print(Align.center(Text(banner_text, style="bold magenta")))

def run_command(command, description, sudo=False, live_output=False):
    is_string_cmd = isinstance(command, str)
    shell = is_string_cmd

    if sudo and not IS_ROOT:
        if is_string_cmd:
            full_command = f"sudo {command}"
        else:
            full_command = ["sudo"] + command
    else:
        full_command = command
        
    cmd_str = full_command if is_string_cmd else ' '.join(full_command)
    
    if DRY_RUN:
        console.print(Align.center(f"[blue]DRY RUN[/blue] Wykonuję: {cmd_str}"))
        return True

    console.print(Align.center(f"-> [yellow]Uruchamiam:[/yellow] {description} ([dim]{cmd_str}[/dim])"))
    try:
        process = subprocess.Popen(
            full_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True, shell=shell
        )
        if process.stdout:
            for line in process.stdout:
                if live_output:
                    console.print(Align.center(f"[dim]  {line.strip()}[/dim]"))
        process.wait()
        if process.returncode != 0:
            console.print(Align.center(f"[red]Błąd[/red] podczas '{description}': Kod {process.returncode}"))
            return False
        return True
    except FileNotFoundError:
        cmd_name = full_command.split()[0] if is_string_cmd else full_command[0]
        console.print(Align.center(f"[red]Błąd[/red]: Polecenie '{cmd_name}' nie znalezione."))
        return False
    except Exception as e:
        console.print(Align.center(f"[red]Nieoczekiwany błąd[/red] podczas '{description}': {e}"))
        return False

def check_dependencies():
    # ... (bez zmian w tej funkcji) ...
    missing_system, missing_go, missing_custom = [], [], []
    deps = {"Zależności Systemowe": (SYSTEM_DEPS, missing_system), "Narzędzia Go": (GO_TOOLS.keys(), missing_go), "Narzędzia Niestandardowe": (CUSTOM_INSTALLS.keys(), missing_custom)}
    tables = []
    for title, (dep_list, missing_list) in deps.items():
        table = Table(title=title, box=box.ROUNDED, show_header=True, header_style="bold cyan", title_justify="left")
        table.add_column("Narzędzie", style="magenta")
        table.add_column("Status", justify="center")
        for dep in dep_list:
            check_path = os.path.join(SHARE_DIR, "testssl.sh", "testssl.sh") if dep == "testssl.sh" else dep
            status_ok = os.path.exists(check_path) if dep == "testssl.sh" else shutil.which(dep)
            if status_ok: table.add_row(dep, "[bold green]✓ ZNALEZIONO[/bold green]")
            else:
                table.add_row(dep, "[bold red]✗ BRAK[/bold red]")
                missing_list.append(dep)
        tables.append(table)
    grid = Columns(tables, align="center", expand=True)
    console.print(Align.center(grid))
    return missing_system, missing_go, missing_custom

def main():
    display_banner()
    console.print(Align.center(Panel.fit("[bold]Instalator VulnMap sprawdzi i zainstaluje zależności.[/bold]", border_style="green")))
    
    # NOWA SEKCJA: Sprawdzanie i prośba o uprawnienia sudo na początku
    if not IS_ROOT:
        # Sprawdzamy, czy jakiekolwiek operacje będą wymagały sudo
        # (kopiowanie, instalacja systemowa, niektóre instalacje customowe)
        needs_sudo_check = True # Uproszczenie - zakładamy, że zawsze może być potrzebne
        if needs_sudo_check:
            info_panel = Panel(
                Text.from_markup(
                    "Niektóre operacje (np. instalacja pakietów, kopiowanie do /usr/local/bin) wymagają uprawnień administratora.\n"
                    "Skrypt poprosi o hasło `sudo` teraz, aby zautomatyzować resztę procesu.",
                    justify="center"
                ),
                title="[bold yellow]Wymagane uprawnienia Sudo[/bold yellow]",
                border_style="yellow"
            )
            console.print(Align.center(info_panel))
            if not run_command(["sudo", "-v"], "Weryfikacja uprawnień sudo..."):
                console.print("[red]Błąd: Nie udało się zweryfikować uprawnień sudo. Przerwano.[/red]")
                sys.exit(1)

    testssl_dir = os.path.join(SHARE_DIR, 'testssl.sh')
    if os.path.exists(testssl_dir) and not os.path.exists(os.path.join(testssl_dir, 'testssl.sh')):
         run_command(['rm', '-rf', testssl_dir], 'Czyszczenie nieudanej instalacji testssl.sh', sudo=True)

    missing_system, missing_go, missing_custom = check_dependencies()

    if not any([missing_system, missing_go, missing_custom]):
        console.print(Align.center("\n[bold green]Wszystkie zależności są już zainstalowane![/bold green]"))
    else:
        console.print(Align.center("\n[bold yellow]Wykryto brakujące zależności.[/bold yellow]"))
        install_confirmed = (ASSUME_YES or NONINTERACTIVE or questionary.confirm("Zainstalować brakujące pakiety?").ask())
        if install_confirmed:
            if missing_system:
                run_command(["apt-get", "update"], "Aktualizacja listy pakietów", sudo=True)
                run_command(["apt-get", "install", "-y"] + missing_system, "Instalacja pakietów systemowych", sudo=True, live_output=True)
            if missing_go:
                for tool in missing_go:
                    run_command(["go", "install", "-v", GO_TOOLS[tool]], f"Instalacja {tool}", live_output=True)
            if missing_custom:
                for tool in missing_custom:
                    tool_info = CUSTOM_INSTALLS[tool]
                    run_command(tool_info["command"], f"Instalacja {tool}", sudo=tool_info["needs_sudo"], live_output=True)

    console.print(Align.center("\n[blue]Instaluję/aktualizuję pakiety Python...[/blue]"))
    run_command(["pip3", "install", "--upgrade"] + PYTHON_PKGS, "Instalacja pakietów pip", live_output=True)

    console.print(Align.center(f"\n[blue]Kopiuję pliki VulnMap do {BIN_DIR} i {SHARE_DIR}...[/blue]"))
    run_command(["mkdir", "-p", SHARE_DIR], f"Tworzenie katalogu {SHARE_DIR}", sudo=True)
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    run_command(["cp", os.path.join(base_dir, "vulnmap.py"), os.path.join(BIN_DIR, "vulnmap")], "Kopiowanie głównego skryptu", sudo=True)
    run_command(["chmod", "+x", os.path.join(BIN_DIR, "vulnmap")], "Nadawanie uprawnień wykonywalnych", sudo=True)
    
    files_to_copy = ["vulnmap_config.py", "vulnmap_utils.py", "vulnmap_report_template.html", "phase0_ingest.py", "phase1_passive.py", "phase2_active_app.py", "phase3_infra.py", "waf_evasion.py"]
    for f_name in files_to_copy:
        src = os.path.join(base_dir, f_name)
        if os.path.exists(src):
            run_command(["cp", src, SHARE_DIR], f"Kopiowanie zasobu: {f_name}", sudo=True)
            
    final_message = Panel(Text.from_markup("[bold green]Instalacja VulnMap zakończona pomyślnie![/bold green]\n\nUruchom narzędzie wpisując: [bold cyan]vulnmap <cel>[/bold cyan]", justify="center"), title="[bold]Gotowe![/bold]", border_style="green")
    console.print(Align.center(final_message))

if __name__ == "__main__":
    main()
