# /usr/local/share/vulnmap/vulnmap_config.py

import os
from typing import Dict, List, Optional

# --- Ścieżki i stałe ---
SHARE_DIR = "/usr/local/share/vulnmap/"
HTML_TEMPLATE_PATH = os.path.join(SHARE_DIR, "vulnmap_report_template.html")

# Inteligentne wykrywanie ścieżki do szablonów Nuclei
_POSSIBLE_TEMPLATE_PATHS = [
    os.path.expanduser("~/.local/nuclei-templates"),
    os.path.expanduser("~/nuclei-templates"),
    "/root/nuclei-templates",
    "/usr/local/share/nuclei-templates"
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
DEBUG_MODE: bool = False

# --- Ustawienia narzędzi (OPSEC & EVASION TUNING) ---
THREADS: int = 2
THREADS_SAFE: int = 1
TOOL_TIMEOUT_SECONDS: int = 2400

# Nuclei Rate Limits
NUCLEI_RATE_LIMIT: int = 25
NUCLEI_RATE_LIMIT_SAFE: int = 5

# SQLMap Tamper Scripts
SQLMAP_TAMPERS_NORMAL: List[str] = ["space2comment", "randomcase"]
SQLMAP_TAMPERS_SAFE: List[str] = [
    "space2comment", "randomcase", "between", "chardoubleencode", 
    "equaltolike", "greatest", "ifnull2ifisnull", "percentage", "charunicodeencode"
]

# Opóźnienia (w sekundach)
REQUEST_DELAY_NORMAL: float = 0.5
REQUEST_DELAY_SAFE: float = 2.0

# --- Ustawienia WafHealthMonitor ---
WAF_CHECK_ENABLED: bool = True
WAF_BLOCK_CODES: List[int] = [403, 406, 429, 503]
WAF_CHECK_INTERVAL_MIN_NORMAL: int = 10
WAF_CHECK_INTERVAL_MAX_NORMAL: int = 30
WAF_CHECK_INTERVAL_MIN_SAFE: int = 20
WAF_CHECK_INTERVAL_MAX_SAFE: int = 60

# --- Ustawienia Skanera Sekretów (JS) ---
JS_SCAN_MAX_SIZE_BYTES: int = 2 * 1024 * 1024  # Maks 2MB na plik, żeby nie zapchać pamięci
SECRETS_PATTERNS: Dict[str, str] = {
    "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Heroku API Key": r"[h|H]eroku.+[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "GitHub Token": r"(gh[pous]_[a-zA-Z0-9]{36,})",
    "Generic Private Key": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
    "Hardcoded Password/Secret": r"(?i)(password|secret|passwd|api_key|access_token)[\s]*[:=][\s]*['\"][a-zA-Z0-9@#$%^&+=]{8,}['\"]"
}

# --- Ustawienia Raportu AI ---
AI_SUMMARY_MIN_SEVERITY: str = "medium"
SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}
AI_PROMPT_TEMPLATE: str = """############################################################
# VULNMAP - PODSUMOWANIE ANALIZY DLA AI
############################################################

Cel skanowania: {target}
Data: {date}

------------------------------------------------------------
PROMPT DLA ASYSTENTA AI
------------------------------------------------------------

Jesteś światowej klasy ekspertem ds. cyberbezpieczeństwa i pentesterem z wieloletnim doświadczeniem w omijaniu zabezpieczeń WAF (WAF Evasion). Twoim zadaniem jest analiza poniższych wyników skanowania z narzędzia VulnMap.

Skup się na następujących punktach:

1.  **Identyfikacja Top 3-5:** Wskaż od 3 do 5 najbardziej krytycznych lub najciekawszych (najbardziej prawdopodobnych do wykorzystania) podatności z listy. Krótko uzasadnij swój wybór.

2.  **Wskazanie Wektorów Ataku (Chaining):** Czy widzisz możliwość połączenia (chaining) kilku z tych podatności w bardziej złożony atak? (np. wykorzystanie Information Disclosure do znalezienia endpointu, który jest podatny na IDOR).

3.  **Analiza False Positives:** Czy któreś ze znalezisk wygląda na potencjalny fałszywy alarm lub "honeypot"?

4.  **Rekomendowane Dalsze Kroki:** Zaproponuj 3 konkretne, manualne kroki, które pentester powinien podjąć w następnej kolejności. Uwzględnij techniki omijania WAF przy weryfikacji manualnej.

Odpowiedź przedstaw w przejrzystej formie, używając Markdown.

------------------------------------------------------------
WYNIKI SKANOWANIA DO ANALIZY (Poziom: {min_severity} i wyższy)
------------------------------------------------------------

{findings}
"""

USER_CUSTOMIZED_THREADS: bool = False
USER_CUSTOMIZED_PROXY: bool = False
USER_CUSTOMIZED_TIMEOUT: bool = False
