# /usr/local/share/vulnmap/vulnmap_config.py

import os
from typing import Dict, List, Optional

# --- Ścieżki i stałe ---
SHARE_DIR = "/usr/local/share/vulnmap/"
HTML_TEMPLATE_PATH = os.path.join(SHARE_DIR, "vulnmap_report_template.html")

# Inteligentne wykrywanie ścieżki do szablonów Nuclei
# Sprawdzamy standardowe lokalizacje, zaczynając od tej z logów użytkownika (.local)
_POSSIBLE_TEMPLATE_PATHS = [
    os.path.expanduser("~/.local/nuclei-templates"), # Nowy domyślny standard dla instalacji user-scope
    os.path.expanduser("~/nuclei-templates"),        # Stary standard
    "/root/nuclei-templates",                        # Częste dla roota/Kal
    "/usr/local/share/nuclei-templates"              # System-wide
]

NUCLEI_TEMPLATES_DIR = next((path for path in _POSSIBLE_TEMPLATE_PATHS if os.path.exists(path)), os.path.expanduser("~/nuclei-templates"))

# --- Globalne zmienne stanu i konfiguracji ---
LOG_FILE: Optional[str] = None
QUIET_MODE: bool = False
OUTPUT_BASE_DIR: str = os.getcwd()
REPORT_DIR: str = ""
SAFE_MODE: bool = False
PROXY: Optional[str] = None
TARGET_INPUT: str = ""

# --- Ustawienia narzędzi ---
THREADS: int = 10
TOOL_TIMEOUT_SECONDS: int = 1800
NUCLEI_RATE_LIMIT: int = 150
NUCLEI_RATE_LIMIT_SAFE: int = 10
SQLMAP_TAMPERS_SAFE: List[str] = ["space2comment", "randomcase", "chardoubleencode"]

# --- Ustawienia WafHealthMonitor ---
WAF_CHECK_ENABLED: bool = True
WAF_CHECK_INTERVAL_MIN_NORMAL: int = 5
WAF_CHECK_INTERVAL_MAX_NORMAL: int = 15
WAF_CHECK_INTERVAL_MIN_SAFE: int = 30
WAF_CHECK_INTERVAL_MAX_SAFE: int = 60

# --- NOWOŚĆ: Ustawienia Raportu AI ---
# Minimalny poziom podatności, który zostanie dołączony do podsumowania dla AI.
AI_SUMMARY_MIN_SEVERITY: str = "medium"

# Słownik do sortowania i filtrowania podatności. Niższa wartość = wyższy priorytet.
SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Szablon promptu dla AI. Zostanie on uzupełniony danymi ze skanu.
AI_PROMPT_TEMPLATE: str = """############################################################
# VULNMAP - PODSUMOWANIE ANALIZY DLA AI
############################################################

Cel skanowania: {target}
Data: {date}

------------------------------------------------------------
PROMPT DLA ASYSTENTA AI
------------------------------------------------------------

Jesteś światowej klasy ekspertem ds. cyberbezpieczeństwa i pentesterem z wieloletnim doświadczeniem. Twoim zadaniem jest analiza poniższych wyników skanowania z narzędzia VulnMap i przygotowanie zwięzłego podsumowania dla innego pentestera.

Skup się na następujących punktach:

1.  **Identyfikacja Top 3-5:** Wskaż od 3 do 5 najbardziej krytycznych lub najciekawszych (najbardziej prawdopodobnych do wykorzystania) podatności z listy. Krótko uzasadnij swój wybór.

2.  **Wskazanie Wektorów Ataku (Chaining):** Czy widzisz możliwość połączenia (chaining) kilku z tych podatności w bardziej złożony atak? (np. wykorzystanie Information Disclosure do znalezienia endpointu, który jest podatny na IDOR).

3.  **Potencjalne "False Positives":** Czy któreś ze znalezisk wygląda na potencjalny fałszywy alarm? Jeśli tak, wskaż które i dlaczego.

4.  **Rekomendowane Dalsze Kroki:** Zaproponuj 3 konkretne, manualne kroki, które pentester powinien podjąć w następnej kolejności, bazując na tych wynikach (np. "Skup się na manualnym teście podatności X na celu Y za pomocą Burp Suite", "Spróbuj eskalować uprawnienia wykorzystując podatność Z").

Odpowiedź przedstaw w przejrzystej formie, używając Markdown.

------------------------------------------------------------
WYNIKI SKANOWANIA DO ANALIZY (Poziom: {min_severity} i wyższy)
------------------------------------------------------------

{findings}
"""

# --- Flagi ręcznych zmian przez użytkownika ---
USER_CUSTOMIZED_THREADS: bool = False
USER_CUSTOMIZED_PROXY: bool = False
USER_CUSTOMIZED_TIMEOUT: bool = False