# 🕵️ Multi-Channel Threat Hunter — Threat Intelligence / OSINT

> **Context:** Automated Threat Intelligence tool that monitors a target term across **three distinct channels** — Darknet, Telegram, and Twitter/X — correlating mentions and exporting structured reports. Built for CTI (Cyber Threat Intelligence) workflows where early detection of brand exposure, credential leaks, or threat actor discussions can significantly reduce response time.


##`Developed by: HKK
---

## `$ cat ./objective.txt`

Automatizar a coleta de **indicadores de exposição** de um alvo (empresa, domínio, produto, pessoa) em canais onde ameaças reais são discutidas:

- **Darknet** — fóruns, marketplaces e sites `.onion` indexados
- **Telegram** — canais públicos onde vazamentos e TTPs são compartilhados
- **Twitter/X** — menções públicas por threat actors, pesquisadores e leaks

O resultado é um **relatório estruturado em CSV** pronto para ingestão em SIEM, planilha ou plataforma de TI.

---

## `$ ls -la`

```
threat-hunter/
├── threat_hunter.py     # Ferramenta principal — orquestrador + módulos de busca
├── requirements.txt     # Dependências Python
└── README.md
```

---

## `$ cat ./architecture.txt`

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MULTI-CHANNEL THREAT HUNTER                          │
│                                                                         │
│   INPUT: target_term (empresa, domínio, hash, CVE, etc.)               │
│                              │                                          │
│              ┌───────────────┼───────────────┐                          │
│              ▼               ▼               ▼                          │
│     ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│     │   Darknet    │  │   Telegram   │  │  Twitter/X   │               │
│     │   (Ahmia)    │  │ (Google dork)│  │   (Nitter)   │               │
│     │              │  │              │  │              │               │
│     │  TOR Session │  │  Clearnet    │  │  Clearnet    │               │
│     │  SOCKS5h     │  │  Session     │  │  Session     │               │
│     └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
│            │                 │                  │                       │
│            └─────────────────┴──────────────────┘                       │
│                              │                                          │
│                     ┌────────▼────────┐                                 │
│                     │  ThreatResult   │  (dataclass estruturado)        │
│                     │  fonte          │                                 │
│                     │  identificador  │                                 │
│                     │  link           │                                 │
│                     │  evidencia      │                                 │
│                     └────────┬────────┘                                 │
│                              │                                          │
│                     ┌────────▼────────┐                                 │
│                     │   CSV Report    │  (utf-8-sig, Excel-ready)       │
│                     └─────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## `$ cat ./design_decisions.md`

### 1. `ThreatResult` — Dataclass como modelo de dados

```python
@dataclass
class ThreatResult:
    fonte: str
    identificador: str
    link: str
    evidencia: str
```

**Por que dataclass e não dict ou namedtuple?**

- **Type hints nativos** — editores sinalizam campos errados em tempo de desenvolvimento
- **`vars(r)`** converte diretamente para dict, tornando a exportação `pd.DataFrame([vars(r) for r in results])` trivial
- Módulos independentes podem retornar `list[ThreatResult]` com contrato claro — sem acoplamento entre os módulos e o orquestrador

Todos os módulos retornam o mesmo tipo, permitindo que o orquestrador faça `results.extend(...)` sem lógica de normalização.

---

### 2. `_build_session()` — Sessões com Retry Automático

```python
RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
```

**Por que retry com backoff?**

Ferramentas de OSINT enfrentam rate limiting (`429`) e instabilidade de servidores frequentemente — especialmente via Tor, onde os circuits podem ser lentos ou cair. O `backoff_factor=1` aplica delays progressivos:

```
1ª tentativa → falha → espera 1s
2ª tentativa → falha → espera 2s
3ª tentativa → falha → espera 4s
```

`status_forcelist` garante retry automático em erros de servidor (5xx) sem código adicional.

**Duas sessões separadas:**

```python
self._clearnet_session = _build_session()                    # Clearnet: Telegram, Twitter
self._tor_session      = _build_session(proxies=TOR_PROXIES) # Tor: Darknet
```

A separação garante que o tráfego de clearnet nunca passe pelo Tor (latência desnecessária) e que o tráfego darknet nunca vaze pelo IP real do operador.

---

### 3. `search_darknet()` — Ahmia via Tor

```python
TOR_PROXIES = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}
```

**Por que `socks5h` e não `socks5`?**

O sufixo `h` significa **hostname resolution via proxy** — o nome de domínio `.onion` é resolvido pelo Tor, não pelo sistema operacional local. Com `socks5` simples, o SO tentaria resolver o `.onion` localmente (sem suporte), causando falha de conexão.

**Por que Ahmia?**

O Ahmia (`ahmia.fi`) é um mecanismo de busca de surface web que indexa conteúdo de sites `.onion`. Permite buscar termos na darknet sem precisar navegar diretamente em sites `.onion` desconhecidos — reduz exposição e simplifica a automação.

```
Surface web → ahmia.fi → índice de .onion → resultados estruturados
```

**Parsing dos resultados:**
```python
items = soup.find_all("li", class_="result")
# Cada item contém: <a> título, <cite> URL .onion, <p> snippet
```

---

### 4. `search_telegram()` — Google Dork para Canais Públicos

```python
query = f'site:t.me "{target}"'
url   = f"https://www.google.com/search?q={query}"
```

**Por que Google dork e não a API do Telegram?**

A API do Telegram requer autenticação e limita buscas a grupos dos quais o usuário é membro. Canais públicos do Telegram são indexados pelo Google via `t.me` — o dork `site:t.me "termo"` retorna menções em canais públicos sem autenticação.

```
Google Search → site:t.me "iFood" → links para mensagens/canais públicos
```

**Limitação:** o Google pode retornar CAPTCHA em volume alto de queries. O `REQUEST_DELAY` e o User-Agent realista mitigam isso.

---

### 5. `search_twitter()` — Nitter como Frontend Alternativo

```python
url = f"https://nitter.privacydev.net/search?q={encoded}"
```

**Por que Nitter e não a API oficial do Twitter/X?**

A API do Twitter/X passou a ser paga em 2023 (mínimo ~$100/mês para tier básico). O Nitter é um frontend open-source que exibe tweets públicos sem autenticação — instâncias públicas permitem scraping de menções sem custo.

```python
tweets = soup.find_all("div", class_="tweet-body")
# username_tag → "a.username"
# content_tag  → "div.tweet-content"
# link_tag     → "a.tweet-link"
```

**Limitação:** instâncias públicas do Nitter podem ficar offline ou ser bloqueadas. Em produção, recomenda-se hospedar uma instância própria ou ter um fallback para outra instância.

---

### 6. `MultiChannelThreatHunter` — Orquestrador com Delay

```python
modules = [
    (search_darknet,  self._tor_session),
    (search_telegram, self._clearnet_session),
    (search_twitter,  self._clearnet_session),
]

for i, (module_fn, session) in enumerate(modules):
    self.results.extend(module_fn(self.target, session))
    if i < len(modules) - 1:
        time.sleep(REQUEST_DELAY)
```

**Por que delay entre módulos?**

Requests em sequência rápida para múltiplos endpoints aumenta a chance de detecção como bot e rate limiting. O `REQUEST_DELAY = 2s` é conservador — para buscas frequentes, aumentar para 5-10s e adicionar jitter (`random.uniform(1, 3)`).

**Por que não paralelo (threading/asyncio)?**

A execução serial é intencional: o Tor é lento e parallelizar sessões Tor pode saturar circuits. Para clearnet, a serialização garante que o Google não veja um burst de queries simultâneas do mesmo IP.

---

### 7. `save()` — Export CSV com `utf-8-sig`

```python
df.to_csv(output_path, index=False, encoding="utf-8-sig")
```

**Por que `utf-8-sig` e não `utf-8`?**

O `utf-8-sig` adiciona um BOM (Byte Order Mark) no início do arquivo. Isso é necessário para que o **Excel** no Windows reconheça automaticamente a codificação e exiba corretamente caracteres especiais (acentos, caracteres de idiomas como russo, árabe — comuns em threat intel).

Com `utf-8` puro, o Excel abre o arquivo com caracteres corrompidos.

---

## `$ cat ./mitre_mapping.yml`

```yaml
# Fase: Reconnaissance (coleta de informações sobre o alvo)
tactics:
  reconnaissance:
    - T1593.001  # Search Social Media
                 # search_twitter(): menções no Twitter/X via Nitter
                 # search_telegram(): canais públicos via Google dork

    - T1596      # Search Open Technical Databases
                 # search_darknet(): indexação Ahmia de sites .onion

    - T1593      # Search Open Websites/Domains
                 # Google dork site:t.me para coleta de menções Telegram

# Nota: essa ferramenta é usada pelo DEFENSOR para monitorar exposição do alvo
# Os mesmos TTPs são usados por threat actors para reconhecimento de vítimas
# Conhecer as técnicas permite construir contramedidas e monitoramento proativo
```

---

## `$ cat ./requirements.txt`

```
requests>=2.31.0
beautifulsoup4>=4.12.0
pandas>=2.0.0
urllib3>=2.0.0
PySocks>=1.7.1      # suporte a socks5h no requests
lxml>=4.9.0         # parser HTML mais rápido que html.parser (opcional)
```

```bash
pip install -r requirements.txt
```

---

## `$ cat ./usage.sh`

### Pré-requisitos

```bash
# Tor deve estar rodando na porta 9050 (módulo Darknet)
# Linux
sudo apt install tor && sudo systemctl start tor

# macOS
brew install tor && brew services start tor

# Verificar que o Tor está ativo
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# Deve retornar {"IsTor": true, ...}
```

### Execução

```python
# Editar o entrypoint no arquivo:
TERMO_ALVO = "NomeDaEmpresa"   # termo a buscar
OUTPUT = Path("./reports/threat_intel.csv")

# Executar
python threat_hunter.py
```

### Output esperado

```
2024-01-15 10:32:01 [INFO] Varrendo Darknet (Ahmia) para: 'iFood'
2024-01-15 10:32:14 [INFO] Darknet: 3 resultado(s) encontrado(s).
2024-01-15 10:32:16 [INFO] Varrendo Telegram (Google dork) para: 'iFood'
2024-01-15 10:32:17 [INFO] Telegram: 7 resultado(s) encontrado(s).
2024-01-15 10:32:19 [INFO] Varrendo Twitter/X (Nitter) para: 'iFood'
2024-01-15 10:32:21 [INFO] Twitter/X: 12 resultado(s) encontrado(s).
2024-01-15 10:32:21 [INFO] Varredura concluída. Total de resultados: 22
2024-01-15 10:32:21 [INFO] Relatório salvo em: ./reports/threat_intel.csv (22 linha(s))
```

### Estrutura do CSV gerado

| Fonte | Identificador | Link/Origem | Evidência/Snippet |
|-------|--------------|-------------|-------------------|
| Darknet (.onion) | Forum post title | abc123.onion/thread/... | "...credenciais ifood..." |
| Telegram (Indexado) | Canal de Leaks BR | t.me/leaksbr | Canal/mensagem contendo menção ao alvo |
| Twitter/X | Tweet de @researcher | https://x.com/... | "encontrei exposed API key de..." |

---

## `$ cat ./extensions.md`

| Feature | Implementação | Impacto |
|---------|--------------|---------|
| Pastebin / GitHub dorks | Novo módulo `search_paste()` | Detectar credenciais e tokens expostos |
| Have I Been Pwned API | `requests.get("https://haveibeenpwned.com/api/v3/breachedaccount/{email}")` | Verificar emails em breaches conhecidos |
| Shodan integration | `shodan.Shodan(API_KEY).search(target)` | Superfície de ataque exposta na internet |
| Alertas automáticos | Microsoft Teams / Slack webhook no `save()` | Notificação em tempo real de novas menções |
| Agendamento | `schedule` ou cron job | Varredura periódica automática (diária/semanal) |
| Deduplicação | Hash SHA256 dos links antes de salvar | Evitar resultados duplicados em runs consecutivos |

---

## `$ cat ./lessons_learned.txt`

```
[+] socks5h é obrigatório para resolução de .onion via Tor — socks5 falha silenciosamente
[+] utf-8-sig garante compatibilidade com Excel — utf-8 puro corrompe acentos no Windows
[+] Dataclass + vars() = pipeline limpo de coleta → dataframe sem transformação manual
[+] Retry com backoff é essencial para OSINT — fontes públicas têm rate limiting imprevisível
[+] Separar sessões Tor/clearnet evita que tráfego público vaze pelo IP real do operador
[-] Nitter depende de instâncias públicas — pode ficar indisponível; considerar instância própria
[-] Google dork para Telegram é bloqueado por CAPTCHA em volume alto — adicionar jitter no delay
[-] Ahmia indexa apenas .onion públicos — marketplaces privados e fóruns fechados não aparecem
[-] Entrypoint hardcoded no __main__ — melhor expor via argparse para uso em pipeline/CI
[→] Próximo nível: argparse CLI, async com httpx, múltiplos termos em batch, deduplicação por hash
```

---

<p align="center">
  <i>Built for CTI workflows · Tor-aware · Multi-channel correlation · CSV-ready output</i>
</p>
