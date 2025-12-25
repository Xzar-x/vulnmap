# /usr/local/share/vulnmap/waf_evasion.py

import random
from typing import List

# Prosty przykład - w przyszłości można to rozbudować o bardziej zaawansowane techniki
XSS_OBFUSCATION_TEMPLATES = [
    "<img src=x onerror={payload}>",
    "<svg onload={payload}>",
    "<body onpageshow={payload}>",
    "<ScRipt>{payload}</ScRipt>",
    "&lt;script&gt;{payload}&lt;/script&gt;",
]

DEFAULT_PAYLOAD = "alert('XSS')"

def select_sqlmap_tamper_scripts() -> List[str]:
    """Wybiera listę skryptów tamper dla SQLMap na podstawie konfiguracji."""
    import vulnmap_config as config
    if config.SAFE_MODE:
        # W trybie bezpiecznym używamy predefiniowanej listy
        return config.SQLMAP_TAMPERS_SAFE
    else:
        # W trybie normalnym możemy użyć jednego, popularnego skryptu lub żadnego
        return ["space2comment"]

def obfuscate_xss_payload(payload: str = DEFAULT_PAYLOAD) -> str:
    """Wybiera losowy szablon i wstawia w niego payload XSS."""
    template = random.choice(XSS_OBFUSCATION_TEMPLATES)
    return template.format(payload=payload)

def get_random_browser_headers() -> dict:
    """Zwraca słownik z realistycznymi nagłówkami przeglądarki."""
    # Ta funkcja może być znacznie bardziej rozbudowana
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    ]
    
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    return headers
