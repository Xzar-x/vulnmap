# /usr/local/share/vulnmap/vulnmap_utils.py

import logging
import random
import sys
import threading
import time
from enum import Enum
from statistics import mean
from typing import Any, Dict, List, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.panel import Panel

# --- Konfiguracja ---
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
console = Console()
LOG_COLOR_MAP = {"INFO": "green", "WARN": "yellow", "ERROR": "red", "DEBUG": "blue"}

# Importuj konfigurację centralną
try:
    import vulnmap_config as config
except ImportError:
    # Fallback dla testowania lokalnego
    class config:
        QUIET_MODE = False
        LOG_FILE = None
        SAFE_MODE = False
        WAF_CHECK_INTERVAL_MIN_NORMAL = 5
        WAF_CHECK_INTERVAL_MAX_NORMAL = 15
        WAF_CHECK_INTERVAL_MIN_SAFE = 15
        WAF_CHECK_INTERVAL_MAX_SAFE = 30


# --- Klasa statusu WAF ---
class WafStatus(Enum):
    GREEN = "GREEN"  # Wszystko OK
    YELLOW = "YELLOW"  # Zwolnienie (Wzrost opóźnień, dziwne błędy 5xx)
    RED = "RED"  # STOP (403, 429, Connection Refused)


# --- Zaawansowany WafHealthMonitor ---
class WafHealthMonitor:
    """
    Inteligentne centrum nerwowe do monitorowania stanu WAF w czasie rzeczywistym.
    Wysyła okresowe 'pingi' do celu, aby sprawdzić, czy nie zostaliśmy zbanowani.
    """

    def __init__(self, baseline_targets: List[str]):
        # Wybieramy tylko unikalne hosty (root urls), max 3 do monitorowania
        self.monitored_urls = list(set(baseline_targets))[:3]
        self.baseline_latency = 0.0
        self.baseline_status_code = 200

        self.status = WafStatus.GREEN
        self.status_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.monitor_thread: Optional[threading.Thread] = None

        # User-Agent do health checków (powinien być stały lub rotowany delikatnie)
        self.health_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (VulnMapMonitor)"

    def get_status(self) -> WafStatus:
        with self.status_lock:
            return self.status

    def _set_status(self, new_status: WafStatus, reason: str = ""):
        with self.status_lock:
            if self.status != new_status:
                self.status = new_status
                color = (
                    "red"
                    if new_status == WafStatus.RED
                    else "yellow" if new_status == WafStatus.YELLOW else "green"
                )
                log_and_echo(
                    f"!!! ZMIANA STATUSU WAF: {new_status.value} ({reason}) !!!",
                    "ERROR" if new_status == WafStatus.RED else "WARN",
                )

    def establish_baseline(self) -> bool:
        """Ustala wielopunktową linię bazową dla normalnych odpowiedzi."""
        if not self.monitored_urls:
            log_and_echo("Brak URLi do monitorowania WAF. Monitor nieaktywny.", "WARN")
            return False

        log_and_echo(
            "Health Check: Kalibracja linii bazowej (pobieranie próbek)...", "INFO"
        )
        latencies = []
        status_codes = []

        for url in self.monitored_urls:
            try:
                start = time.time()
                resp = requests.get(
                    url,
                    headers={"User-Agent": self.health_ua},
                    timeout=10,
                    verify=False,
                )
                latencies.append(time.time() - start)
                status_codes.append(resp.status_code)
            except Exception as e:
                log_and_echo(f"Błąd kalibracji dla {url}: {e}", "DEBUG")

        if not latencies:
            log_and_echo(
                "Nie udało się połączyć z żadnym celem podczas kalibracji! Zakładam RED.",
                "ERROR",
            )
            self._set_status(WafStatus.RED, "Brak połączenia przy starcie")
            return False

        self.baseline_latency = mean(latencies)
        # Bierzemy najczęstszy kod statusu (moda)
        self.baseline_status_code = max(set(status_codes), key=status_codes.count)

        log_and_echo(
            f"Linia bazowa ustalona: Latency={self.baseline_latency:.3f}s, Status={self.baseline_status_code}",
            "INFO",
        )
        return True

    def _check_health(self):
        """Wykonuje pojedyncze sprawdzenie zdrowia."""
        # Wybierz losowy cel z monitorowanych
        target = random.choice(self.monitored_urls)

        try:
            start = time.time()
            resp = requests.get(
                target, headers={"User-Agent": self.health_ua}, timeout=10, verify=False
            )
            latency = time.time() - start

            # --- ANALIZA STANU ---

            # 1. Sprawdzenie twardych blokad (RED)
            if resp.status_code in [403, 429]:
                self._set_status(
                    WafStatus.RED, f"Wykryto kod {resp.status_code} (Block/RateLimit)"
                )
                return

            # 2. Sprawdzenie anomalii czasowych (YELLOW)
            # Jeśli jest 3x wolniej niż bazowo (i bazowo nie było super szybko < 0.1s)
            if self.baseline_latency > 0.1 and latency > (self.baseline_latency * 3.0):
                if self.status == WafStatus.GREEN:
                    self._set_status(
                        WafStatus.YELLOW,
                        f"Wysokie opóźnienie: {latency:.2f}s (bazowe: {self.baseline_latency:.2f}s)",
                    )
                return

            # 3. Sprawdzenie zmiany kodu statusu (np. 200 -> 500)
            if (
                resp.status_code != self.baseline_status_code
                and resp.status_code >= 500
            ):
                if self.status == WafStatus.GREEN:
                    self._set_status(
                        WafStatus.YELLOW, f"Błąd serwera: {resp.status_code}"
                    )
                return

            # 4. Powrót do normy (GREEN)
            if self.status != WafStatus.GREEN:
                # Wymagamy np. 2 poprawnych checków pod rząd w realnym rozwiązaniu, tu upraszczamy
                self._set_status(WafStatus.GREEN, "Parametry wróciły do normy")

        except requests.exceptions.ConnectionError:
            self._set_status(WafStatus.RED, "Odrzucono połączenie (Connection Refused)")
        except requests.exceptions.Timeout:
            if self.status == WafStatus.GREEN:
                self._set_status(WafStatus.YELLOW, "Timeout połączenia")
        except Exception as e:
            log_and_echo(f"Błąd health check: {e}", "DEBUG")

    def run_monitor(self):
        """Pętla główna wątku monitorującego."""
        while not self.stop_event.is_set():
            # Interwały zależą od trybu i aktualnego stanu
            min_int, max_int = (
                (config.WAF_CHECK_INTERVAL_MIN_SAFE, config.WAF_CHECK_INTERVAL_MAX_SAFE)
                if config.SAFE_MODE
                else (
                    config.WAF_CHECK_INTERVAL_MIN_NORMAL,
                    config.WAF_CHECK_INTERVAL_MAX_NORMAL,
                )
            )

            # Jeśli jesteśmy w stanie YELLOW/RED, sprawdzaj rzadziej (żeby nie pogarszać sytuacji)
            # W poprzedniej wersji było częściej, ale przy banie lepiej zwolnić całkowicie
            if self.get_status() != WafStatus.GREEN:
                min_int *= 2
                max_int *= 2

            self._check_health()

            sleep_time = random.uniform(min_int, max_int)
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

    # Filtrowanie debugów w trybie cichym
    if level.upper() == "DEBUG" and not getattr(config, "DEBUG_MODE", False):
        return

    if level.upper() in ["ERROR", "WARN"] or not config.QUIET_MODE:
        console.print(f"[{color}]{message}[/{color}]")

    if config.LOG_FILE:
        logging.log(log_level, message)
