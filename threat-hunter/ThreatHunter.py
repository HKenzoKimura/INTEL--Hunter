import logging
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pandas as pd
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Configuração de logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constantes e configuração
# ---------------------------------------------------------------------------
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)

REQUEST_DELAY = 2  # segundos entre módulos


# ---------------------------------------------------------------------------
# Modelo de resultado
# ---------------------------------------------------------------------------
@dataclass
class ThreatResult:
    fonte: str
    identificador: str
    link: str
    evidencia: str


# ---------------------------------------------------------------------------
# Sessões HTTP
# ---------------------------------------------------------------------------
def _build_session(proxies: Optional[dict] = None) -> requests.Session:
    """Cria uma Session com retry automático e headers padrão."""
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=RETRY_STRATEGY)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    if proxies:
        session.proxies.update(proxies)
    return session


# ---------------------------------------------------------------------------
# Módulos de busca
# ---------------------------------------------------------------------------
def search_darknet(target: str, session: requests.Session) -> list[ThreatResult]:
    """Consulta o Ahmia via Tor para indexar resultados da Darknet."""
    logger.info("Varrendo Darknet (Ahmia) para: '%s'", target)
    results: list[ThreatResult] = []

    encoded = urllib.parse.quote_plus(target)
    url = f"https://ahmia.fi/search/?q={encoded}"

    try:
        response = session.get(url, timeout=15)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        items = soup.find_all("li", class_="result")

        for item in items:
            title = item.find("a")
            cite = item.find("cite")
            snippet = item.find("p")

            results.append(
                ThreatResult(
                    fonte="Darknet (.onion)",
                    identificador=title.get_text(strip=True) if title else "Sem título",
                    link=cite.get_text(strip=True) if cite else "",
                    evidencia=snippet.get_text(strip=True) if snippet else "",
                )
            )

        logger.info("Darknet: %d resultado(s) encontrado(s).", len(results))

    except requests.exceptions.ConnectionError:
        logger.error(
            "Não foi possível conectar ao Tor/Ahmia. "
            "Certifique-se de que o serviço Tor está rodando na porta 9050."
        )
    except requests.exceptions.Timeout:
        logger.error("Timeout ao acessar o Ahmia.")
    except requests.exceptions.HTTPError as exc:
        logger.error("Erro HTTP no módulo Darknet: %s", exc)

    return results


def search_telegram(target: str, session: requests.Session) -> list[ThreatResult]:
    """Busca canais públicos do Telegram indexados pelo Google via dork."""
    logger.info("Varrendo Telegram (Google dork) para: '%s'", target)
    results: list[ThreatResult] = []

    query = urllib.parse.quote_plus(f'site:t.me "{target}"')
    url = f"https://www.google.com/search?q={query}"

    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        blocks = soup.find_all("div", class_="g")

        for block in blocks:
            link_tag = block.find("a")
            title_tag = block.find("h3")
            if not (link_tag and title_tag):
                continue

            results.append(
                ThreatResult(
                    fonte="Telegram (Indexado)",
                    identificador=title_tag.get_text(strip=True),
                    link=link_tag.get("href", ""),
                    evidencia="Canal/mensagem contendo menção ao alvo.",
                )
            )

        logger.info("Telegram: %d resultado(s) encontrado(s).", len(results))

    except requests.exceptions.Timeout:
        logger.error("Timeout ao acessar o Google (módulo Telegram).")
    except requests.exceptions.HTTPError as exc:
        logger.error("Erro HTTP no módulo Telegram: %s", exc)

    return results


def search_twitter(target: str, session: requests.Session) -> list[ThreatResult]:
    """Busca menções no Twitter/X via instância pública do Nitter."""
    logger.info("Varrendo Twitter/X (Nitter) para: '%s'", target)
    results: list[ThreatResult] = []

    encoded = urllib.parse.quote_plus(target)
    url = f"https://nitter.privacydev.net/search?q={encoded}"

    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        tweets = soup.find_all("div", class_="tweet-body")

        for tweet in tweets:
            username_tag = tweet.find("a", class_="username")
            content_tag = tweet.find("div", class_="tweet-content")
            link_tag = tweet.find("a", class_="tweet-link")

            username = username_tag.get_text(strip=True) if username_tag else "Anônimo"
            content = content_tag.get_text(strip=True) if content_tag else ""
            href = link_tag.get("href", "") if link_tag else ""

            results.append(
                ThreatResult(
                    fonte="Twitter/X",
                    identificador=f"Tweet de {username}",
                    link=f"https://x.com{href}" if href else "N/A",
                    evidencia=content,
                )
            )

        logger.info("Twitter/X: %d resultado(s) encontrado(s).", len(results))

    except requests.exceptions.Timeout:
        logger.error("Timeout ao acessar o Nitter.")
    except requests.exceptions.HTTPError as exc:
        logger.error("Erro HTTP no módulo Twitter/X: %s", exc)

    return results


# ---------------------------------------------------------------------------
# Orquestrador principal
# ---------------------------------------------------------------------------
class MultiChannelThreatHunter:
    def __init__(self, target_term: str) -> None:
        self.target = target_term
        self._clearnet_session = _build_session()
        self._tor_session = _build_session(proxies=TOR_PROXIES)
        self.results: list[ThreatResult] = []

    def run(self) -> None:
        """Executa todos os módulos de busca com delay entre eles."""
        modules = [
            (search_darknet, self._tor_session),
            (search_telegram, self._clearnet_session),
            (search_twitter, self._clearnet_session),
        ]

        for i, (module_fn, session) in enumerate(modules):
            self.results.extend(module_fn(self.target, session))
            if i < len(modules) - 1:
                time.sleep(REQUEST_DELAY)

        logger.info("Varredura concluída. Total de resultados: %d", len(self.results))

    def save(self, output_path: str | Path) -> None:
        """Exporta os resultados para CSV."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.results:
            logger.warning("Nenhum resultado para salvar.")
            return

        df = pd.DataFrame([vars(r) for r in self.results])
        df.columns = ["Fonte", "Identificador", "Link/Origem", "Evidência/Snippet"]
        df.to_csv(output_path, index=False, encoding="utf-8-sig")

        logger.info("Relatório salvo em: %s (%d linha(s))", output_path, len(df))


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Multi-Channel Threat Hunter")
    parser.add_argument("target", help="Termo a Buscar (empresa, domínio, hash...)")
    parser.add_argument("--output", default="./reports/threat_intel.csv")
    args = parser.parse_args()
    
    hunter = MultiChannelThreatHunter(target_term=args.target)
    