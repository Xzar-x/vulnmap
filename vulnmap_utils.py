# /usr/local/share/vulnmap/vulnmap_utils.py

import logging
import random
import sys
import threading
import time
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.console import Console

# --- Konfiguracja ---
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
console = Console()
LOG_COLOR_MAP = {"INFO": "green", "WARN": "yellow", "ERROR": "red", "DEBUG": "blue"}

# Importuj konfigurację centralną
try:
    import vulnmap_config as config
except ImportError:
    # Fallback dla testowania lokalnego
    import vulnmap_config_fallback as config

# --- Klasa statusu WAF ---
class WafStatus(Enum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"

# --- Zaawansowany WafHealthMonitor ---
class WafHealthMonitor:
    """
    Inteligentne centrum nerwowe do monitorowania stanu WAF w czasie rzeczywistym.
    Działa w oparciu o maszynę stanów (GREEN, YELLOW, RED) i dynamicznie
    reaguje na anomalie i blokady.
    """

    def __init__(self, baseline_targets: List[str]):
        self.baseline_targets = baseline_targets
        self.baselines: Dict[str, Dict[str, Any]] = {}
        self.status = WafStatus.GREEN
        self.status_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.monitor_thread: Optional[threading.Thread] = None

    def get_status(self) -> WafStatus:
        with self.status_lock:
            return self.status

    def _set_status(self, new_status: WafStatus):
        with self.status_lock:
            if self.status != new_status:
                self.status = new_status
                log_and_echo(f"WAF Health Monitor: Zmieniono status na {new_status.value}", "WARN")

    def establish_baseline(self) -> bool:
        """Ustala wielopunktową linię bazową dla normalnych odpowiedzi."""
        log_and_echo("Health Check: Ustalam wielopunktową linię bazową...", "INFO")
        # TODO: Zaimplementować logikę ustalania linii bazowej
        # Dla każdego celu w self.baseline_targets, wyślij zapytanie
        # i zapisz status, hash, długość i czas odpowiedzi.
        # Jeśli nie uda się ustalić dla >50% celów, zwróć False.
        console.print("[yellow]Funkcjonalność WAF Monitora jest w budowie.[/yellow]")
        return True # Placeholder

    def _check_against_baseline(self):
        """Porównuje aktualne odpowiedzi z linią bazową i aktualizuje stan."""
        # TODO: Zaimplementować logikę sprawdzania
        # 1. Wybierz losowy cel z linii bazowej.
        # 2. Wyślij zapytanie.
        # 3. Porównaj z zapisanym hashem, statusem, itp.
        # 4. Na podstawie odchyleń, zaktualizuj stan na GREEN, YELLOW lub RED.
        pass # Placeholder

    def run_monitor(self):
        """Pętla główna wątku monitorującego."""
        while not self.stop_event.is_set():
            self._check_against_baseline()
            
            min_interval, max_interval = (
                (config.WAF_CHECK_INTERVAL_MIN_SAFE, config.WAF_CHECK_INTERVAL_MAX_SAFE)
                if config.SAFE_MODE
                else (config.WAF_CHECK_INTERVAL_MIN_NORMAL, config.WAF_CHECK_INTERVAL_MAX_NORMAL)
            )
            
            # W stanie YELLOW sprawdzaj częściej
            if self.get_status() == WafStatus.YELLOW:
                min_interval /= 2
                max_interval /= 2
            
            sleep_time = random.uniform(min_interval, max_interval)
            self.stop_event.wait(sleep_time)

    def start(self):
        if self.establish_baseline():
            self.monitor_thread = threading.Thread(target=self.run_monitor, daemon=True)
            self.monitor_thread.start()
            log_and_echo("WAF Health Monitor został uruchomiony w tle.", "INFO")

    def stop(self):
        self.stop_event.set()
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        log_and_echo("WAF Health Monitor został zatrzymany.", "INFO")

def log_and_echo(message: str, level: str = "INFO"):
    """Loguje wiadomość do pliku i wyświetla ją w konsoli."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    color = LOG_COLOR_MAP.get(level.upper(), "white")
    
    if level.upper() in ["ERROR", "WARN"] or not config.QUIET_MODE:
        console.print(f"[{color}]{message}[/{color}]")

    if config.LOG_FILE:
        logging.log(log_level, message)
