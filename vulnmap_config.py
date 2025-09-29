# /usr/local/share/vulnmap/vulnmap_config.py

import os
from typing import List, Optional

# --- Ścieżki i stałe ---
SHARE_DIR = "/usr/local/share/vulnmap/"
HTML_TEMPLATE_PATH = os.path.join(SHARE_DIR, "vulnmap_report_template.html")
# Ścieżka do szablonów nuclei może wymagać konfiguracji przez użytkownika
NUCLEI_TEMPLATES_DIR = os.path.expanduser("~/nuclei-templates")

# --- Globalne zmienne stanu i konfiguracji ---
LOG_FILE: Optional[str] = None
QUIET_MODE: bool = False
OUTPUT_BASE_DIR: str = os.getcwd()
REPORT_DIR: str = ""
SAFE_MODE: bool = False
PROXY: Optional[str] = None
TARGET_INPUT: str = "" # Może to być URL, domena lub ścieżka do pliku JSON

# --- Ustawienia narzędzi ---
THREADS: int = 10
TOOL_TIMEOUT_SECONDS: int = 1800

# Ustawienia specyficzne dla narzędzi
NUCLEI_RATE_LIMIT: int = 150
NUCLEI_RATE_LIMIT_SAFE: int = 10

# Lista skryptów tamper dla SQLMap w trybie Safe Mode
SQLMAP_TAMPERS_SAFE: List[str] = ["space2comment", "randomcase", "chardoubleencode"]

# --- Ustawienia WafHealthMonitor ---
WAF_CHECK_ENABLED: bool = True
# Interwały w sekundach
WAF_CHECK_INTERVAL_MIN_NORMAL: int = 5
WAF_CHECK_INTERVAL_MAX_NORMAL: int = 15
WAF_CHECK_INTERVAL_MIN_SAFE: int = 30
WAF_CHECK_INTERVAL_MAX_SAFE: int = 60

# --- Flagi ręcznych zmian przez użytkownika ---
# (Dodamy je w miarę potrzeby, gdy będziemy budować menu ustawień)
USER_CUSTOMIZED_THREADS: bool = False
USER_CUSTOMIZED_PROXY: bool = False
USER_CUSTOMIZED_TIMEOUT: bool = False
