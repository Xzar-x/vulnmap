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
    # Kali Linux 2024+ fix
    print("BŁĄD: Podstawowe pakiety (rich, questionary, pyfiglet) nie są zainstalowane.")
    print("Próbuję zainstalować je automatycznie z flagą --break-system-packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", "rich", "questionary", "pyfiglet", "typer", "requests"])
        print("Pakiety zainstalowane pomyślnie. Uruchom skrypt ponownie.")
        sys.exit(0)
    except subprocess.CalledProcessError:
        print("Nie udało się zainstalować pakietów. Zainstaluj ręcznie: sudo pip3 install rich questionary pyfiglet typer requests --break-system-packages")
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

# Repozytoria customowe
CUSTOM_INSTALLS = {
    "wpscan": {"command": "gem install wpscan", "needs_sudo": True},
    "testssl.sh": {"command": f"git clone --depth 1 https://github.com/drwetter/testssl.sh.git {os.path.join(SHARE_DIR, 'testssl.sh')}", "needs_sudo": True},
    "lfimap": {"command": f"git clone https://github.com/hansmach1ne/LFImap.git {os.path.join(SHARE_DIR, 'lfimap')}", "needs_sudo": True}
}

def display_banner():
    f = Figlet(font="slant")
    banner_text = f.renderText("VulnMap\nInstaller")
    console.print(Align.center(Text(banner_text, style="bold magenta")))

def run_command(command, description, sudo=False, live_output=False, ignore_errors=False):
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
            if ignore_errors:
                console.print(Align.center(f"[yellow]Ostrzeżenie[/yellow]: '{description}' zwrócił błąd, ale kontynuuję."))
                return True
            else:
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
    missing_system, missing_go, missing_custom = [], [], []
    deps = {"Zależności Systemowe": (SYSTEM_DEPS, missing_system), "Narzędzia Go": (GO_TOOLS.keys(), missing_go), "Narzędzia Niestandardowe": (CUSTOM_INSTALLS.keys(), missing_custom)}
    tables = []
    for title, (dep_list, missing_list) in deps.items():
        table = Table(title=title, box=box.ROUNDED, show_header=True, header_style="bold cyan", title_justify="left")
        table.add_column("Narzędzie", style="magenta")
        table.add_column("Status", justify="center")
        for dep in dep_list:
            if dep == "testssl.sh":
                check_path = os.path.join(SHARE_DIR, "testssl.sh", "testssl.sh")
                status_ok = os.path.exists(check_path)
            elif dep == "lfimap":
                check_path = os.path.join(SHARE_DIR, "lfimap")
                status_ok = os.path.exists(check_path) and os.listdir(check_path)
            elif dep == "wpscan":
                status_ok = shutil.which("wpscan") is not None
            else:
                status_ok = shutil.which(dep) is not None

            if status_ok: table.add_row(dep, "[bold green]✓ ZNALEZIONO[/bold green]")
            else:
                table.add_row(dep, "[bold red]✗ BRAK[/bold red]")
                missing_list.append(dep)
        tables.append(table)
    grid = Columns(tables, align="center", expand=True)
    console.print(Align.center(grid))
    return missing_system, missing_go, missing_custom

def cleanup_broken_installs():
    """Usuwa uszkodzone instalacje."""
    lfimap_dir = os.path.join(SHARE_DIR, "lfimap")
    if os.path.exists(lfimap_dir):
        # Sprawdź rekurencyjnie czy jest plik lfimap.py
        found = False
        for root, dirs, files in os.walk(lfimap_dir):
            if "lfimap.py" in files or "LFImap.py" in files:
                found = True
                break
        if not found:
            run_command(['rm', '-rf', lfimap_dir], 'Usuwanie uszkodzonej instalacji LFImap', sudo=True)

    testssl_dir = os.path.join(SHARE_DIR, "testssl.sh")
    if os.path.exists(testssl_dir) and (not os.listdir(testssl_dir) or not os.path.exists(os.path.join(testssl_dir, "testssl.sh"))):
        run_command(['rm', '-rf', testssl_dir], 'Usuwanie uszkodzonej instalacji TestSSL', sudo=True)

def main():
    display_banner()
    console.print(Align.center(Panel.fit("[bold]Instalator VulnMap sprawdzi i zainstaluje zależności.[/bold]", border_style="green")))
    
    cleanup_broken_installs()
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
                    if tool == "lfimap":
                        target_dir = os.path.join(SHARE_DIR, 'lfimap')
                        if os.path.exists(target_dir):
                            run_command(["rm", "-rf", target_dir], "Czyszczenie folderu LFImap przed instalacją", sudo=True)
                    tool_info = CUSTOM_INSTALLS[tool]
                    run_command(tool_info["command"], f"Instalacja {tool}", sudo=tool_info["needs_sudo"], live_output=True)

    console.print(Align.center("\n[blue]Instaluję/aktualizuję pakiety Python...[/blue]"))
    pip_command = ["pip3", "install", "--upgrade", "--break-system-packages"] + PYTHON_PKGS
    run_command(pip_command, "Instalacja pakietów pip (ignorowanie konfliktów Kali)", live_output=True, ignore_errors=True)

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

    console.print(Align.center("\n[blue]Naprawiam uprawnienia plików współdzielonych...[/blue]"))
    run_command(["chmod", "-R", "a+rX", SHARE_DIR], "Naprawa uprawnień w /usr/local/share/vulnmap", sudo=True)

    console.print(Align.center("\n[blue]Konfiguruję skróty globalne dla narzędzi...[/blue]"))
    
    # 1. LFIMap - Inteligentne, rekurencyjne szukanie pliku startowego
    lfimap_root_dir = os.path.join(SHARE_DIR, "lfimap")
    lfimap_bin = os.path.join(BIN_DIR, "lfimap")
    
    found_script_path = None
    found_script_dir = None
    found_script_name = None

    if os.path.exists(lfimap_root_dir):
        for root, dirs, files in os.walk(lfimap_root_dir):
            for file in files:
                if file.lower() == "lfimap.py":
                    found_script_path = os.path.join(root, file)
                    found_script_dir = root
                    found_script_name = file
                    break
            if found_script_path:
                break
    
    if found_script_path:
        # Tworzymy wrapper, który wchodzi do folderu ze skryptem (CD)
        # To jest kluczowe, jeśli lfimap.py jest w podkatalogu!
        wrapper_content = f"""#!/bin/sh
cd {found_script_dir}
exec python3 {found_script_name} "$@"
"""
        try:
            with open("lfimap_wrapper.tmp", "w") as f:
                f.write(wrapper_content)
            run_command(["mv", "lfimap_wrapper.tmp", lfimap_bin], "Tworzenie komendy 'lfimap'", sudo=True)
            run_command(["chmod", "+x", lfimap_bin], "Nadawanie uprawnień wykonywalnych", sudo=True)
            console.print(f"[green]✓ Znaleziono LFImap w: {found_script_path}[/green]")
        except Exception as e:
            console.print(f"[red]Błąd przy tworzeniu wrappera: {e}[/red]")
    else:
        console.print(Align.center(f"[bold red]KRYTYCZNE: Nie znaleziono lfimap.py wewnątrz {lfimap_root_dir}![/bold red]"))
        # Diagnostyka
        if os.path.exists(lfimap_root_dir):
            run_command(["find", lfimap_root_dir, "-maxdepth", "3"], "Lista plików (debug)", live_output=True)
    
    # 2. TestSSL
    testssl_path = os.path.join(SHARE_DIR, "testssl.sh", "testssl.sh")
    testssl_bin = os.path.join(BIN_DIR, "testssl")
    if os.path.exists(testssl_path):
        run_command(["ln", "-sf", testssl_path, testssl_bin], "Tworzenie komendy 'testssl'", sudo=True)

    # WERYFIKACJA KOŃCOWA
    console.print(Align.center("\n[blue]Weryfikacja instalacji:[/blue]"))
    if os.path.exists(lfimap_bin):
        console.print(f"[green]✓ Skrót LFImap istnieje: {lfimap_bin}[/green]")
    else:
        console.print(f"[red]✗ Skrót LFImap nie został utworzony![/red]")

    final_message = Panel(Text.from_markup("[bold green]Instalacja VulnMap zakończona pomyślnie![/bold green]\n\nJEŚLI NADAL NIE WIDZISZ KOMEND, WPISZ:\n[bold yellow]hash -r[/bold yellow]", justify="center"), title="[bold]Gotowe![/bold]", border_style="green")
    console.print(Align.center(final_message))

if __name__ == "__main__":
    main()
