# Agentic-Recon — Reconocimiento ofensivo asistido por agentes, bajo RoE estricto

[![Go](https://img.shields.io/badge/go-1.23%2B-00ADD8?logo=go)](https://go.dev/)
[![Deps](https://img.shields.io/badge/deps-m%C3%ADnimas%20y%20pinneadas-green)](#3-ficha-t%C3%A9cnica)
[![Uso](https://img.shields.io/badge/uso-solo%20autorizado-orange)](#16-uso-responsable)

**Agentic-Recon** es una plataforma de reconocimiento ofensivo (EASM del lado del
atacante) para **engagements autorizados**: descubre y valida la superficie de
ataque de un alcance definido en un `scope.yaml` firmado, con un **motor de
políticas determinista** que garantiza que ninguna acción sale de ese alcance, y
agentes LLM **opcionales** que aceleran el triaje sobre datos ya estructurados.

Ocupa la **fase de Reconocimiento / Acceso Inicial** del ciclo de un engagement:

```
   [Agentic-Recon]                      [ReverseShell]
   descubrir + validar superficie  →  acceso inicial (manual/RoE)  →  C2 post-acceso
   ─────────────────────────────        ────────────────────────────
   EASM ofensivo, pre-acceso           F3+: implant, listener, teamserver
```

> [!WARNING]
> Herramienta dual-use. Solo para: activos de tu propiedad, laboratorios/CTF,
> o engagements con **autorización escrita y alcance firmado**. El `scope.yaml`
> es un contrato: sin `authorization.reference`, la herramienta no arranca.
> Fuera de alcance por diseño: explotación, ataques de credenciales,
> auto-propagación y cualquier mecanismo de ocultamiento frente al dueño
> legítimo del sistema.

---

## Tabla de contenidos

1. [Posicionamiento y límites](#1-posicionamiento-y-límites)
2. [Principios de diseño no negociables](#2-principios-de-diseño-no-negociables)
3. [Ficha técnica](#3-ficha-técnica)
4. [Arquitectura — 6 capas](#4-arquitectura--6-capas)
5. [El contrato: `scope.yaml`](#5-el-contrato-scopeyaml)
6. [Capa 2 — Motor de políticas](#6-capa-2--motor-de-políticas)
7. [Capa 4 — Almacén de estado](#7-capa-4--almacén-de-estado)
8. [Capa 3 — Pipeline determinista](#8-capa-3--pipeline-determinista)
9. [Capa 5 — Toolbox tipada](#9-capa-5--toolbox-tipada)
10. [Capa 6 — Agentes](#10-capa-6--agentes)
11. [Evidencia y auditoría](#11-evidencia-y-auditoría)
12. [Salida: reporte del engagement](#12-salida-reporte-del-engagement)
13. [Estructura del repositorio](#13-estructura-del-repositorio)
14. [Roadmap](#14-roadmap)
15. [Qué no se construirá](#15-qué-no-se-construirá)
16. [Uso responsable](#16-uso-responsable)

---

## 1. Posicionamiento y límites

**Es**: descubrimiento pasivo y validación de bajo impacto sobre un alcance
explícito — subdominios, servicios web, tecnologías, endpoints expuestos,
documentación filtrada (Swagger/OpenAPI), configuraciones anómalas — con
hipótesis priorizadas que señalan **rutas hacia el acceso inicial**. El
operador ejecuta el acceso; esta herramienta lo prepara y lo documenta.

**No es**: no explota vulnerabilidades, no lanza credenciales, no hace
post-explotación (eso vive en ReverseShell, post-acceso), y no se auto-propaga.

**Relación con el "sigilo"**: el perfil de ruido de una campaña es un
**parámetro del RoE acordado con el cliente** (purple team, detection testing,
requisitos de estabilidad del entorno). La herramienta implementa el perfil
acordado — no existe para ocultarse de un dueño que no autorizó la prueba.

---

## 2. Principios de diseño no negociables

1. **Scope-first.** Sin `scope.yaml` con `authorization.reference`, nada
   corre. Default-deny: lo que no está explícitamente dentro, está fuera.
2. **El policy engine es determinista.** Cero IA en la capa de control. Los
   agentes proponen; el motor dispone.
3. **Evidence-everything.** Cada request de red —humana, módulo o agente—
   genera un registro inmutable (actor, herramienta, target, razón).
4. **Human-in-the-loop para lo intrusivo.** Clasificación de riesgo por
   herramienta; lo INTRUSIVE se pausa hasta aprobación explícita.
5. **El LLM es opcional.** El pipeline determinista + triaje manual es 100%
   funcional sin IA. Los agentes aceleran; nunca habilitan.
6. **Sin bash libre.** Los agentes solo ven el catálogo tipado de la Capa 5;
   cada llamada pasa por el policy engine.
7. **Pausable y reanudable.** Todo el estado vive en la Capa 4; una campaña
   se interrumpe y continúa sin repetir trabajo.

---

## 3. Ficha técnica

| Aspecto | Valor |
|---|---|
| Lenguaje | Go 1.26+ (stdlib-first; el piso lo fija `modernc.org/sqlite`) |
| Dependencias externas | **Mínimas y justificadas**: `gopkg.in/yaml.v3` (scope.yaml — stdlib no trae YAML), `modernc.org/sqlite` (SQLite pure-Go, mantiene `CGO_ENABLED=0` y el cross-compile). Nada más. |
| LLM | Vía REST con `net/http` (Anthropic o API compatible-OpenAI) — sin SDKs, sin deps extra |
| Base de datos | SQLite (archivo por campaña o único con `campaign_id`) |
| Binarios | Estáticos (`CGO_ENABLED=0`), cross-compilables |
| Config | `scope.yaml` (gitignored — contiene nombres de clientes) + `scope.example.yaml` versionado |
| Gates | `gofmt` / `go vet` / `go test -race` (CI) / `go build` |

---

## 4. Arquitectura — 6 capas

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. INTERFAZ DEL OPERADOR      CLI: campaña, cola de aprobaciones,  │
│    (CLI primero)              triaje manual, reporte                │
├─────────────────────────────────────────────────────────────────────┤
│ 6. AGENTES (opcional)         triaje orquestador + especialistas    │
│                               ReAct con presupuesto de pasos/tokens  │
├─────────────────────────────────────────────────────────────────────┤
│ 5. TOOLBOX                    catálogo tipado y cerrado — sin bash    │
├─────────────────────────────────────────────────────────────────────┤
│ 4. ALMACÉN                    SQLite: assets + grafo + evidencia +  │
│    (memoria compartida)       máquina de estados                    │
├─────────────────────────────────────────────────────────────────────┤
│ 3. PIPELINE DETERMINISTA      módulos nativos + wrappers (pre-flight)│
├─────────────────────────────────────────────────────────────────────┤
│ 2. POLICY ENGINE ◀────────── TODA acción pasa por aquí ◀────────────┤
│    (determinista, cero IA)    scope · rate+jitter · riesgo · gate    │
└─────────────────────────────────────────────────────────────────────┘
                              ▲
                    ninguna capa salta a la 2
```

**Nota honesta sobre el choke point**: los binarios externos (subfinder, dnsx…)
abren sus propios sockets — ningún motor puede interceptarlos por dentro. Por
eso el enforcement es triple (§6.1), y los módulos críticos son **nativos**,
donde el policy engine sí es el único egress literal.

---

## 5. El contrato: `scope.yaml`

```yaml
# scope.example.yaml — plantilla. El real va GITIGNORED (nombra clientes).

authorization:
  reference: "ROE-2026-011-firma"     # OBLIGATORIO: id del RoE firmado
  window:                            # la campaña se niega a correr fuera
    start: 2026-11-01T00:00:00Z
    end:   2026-11-30T23:59:59Z

scope:
  domains:            # dominios raíz autorizados (los subdominios derivan)
    - example.com
    - example.org
  ips:                # rangos autorizados explícitos
    - 203.0.113.0/24
  exclude:            # exclusión dura, evaluada antes que la inclusión
    - partner.example.com
    - 203.0.113.7
  sources:            # terceros consultables (allow-list: lo ausente está prohibido)
    - crt.sh
    - dns-resolver       # resolvers recursivos públicos/propio
    # - virustotal      # DESACTIVADO: algunos clientes lo prohíben

policy:
  risk_levels:        # qué clases de riesgo están habilitadas en esta campaña
    - PASSIVE
    - LOW_IMPACT
    # - INTRUSIVE      # requiere approval gate por acción
  rate:
    requests_per_second: 5      # global de campaña
    per_host_per_second: 1      # por target
    jitter_ms: 750              # ± spread aleatorio entre requests
  noise_profile: "purple-team"   # perfil acordado en el RoE (documental)

budgets:
  agent_max_steps_per_hypothesis: 8
  campaign_max_tokens: 2_000_000

llm:                  # OPCIONAL — sin esta sección el triaje es manual
  provider: "anthropic"          # anthropic | openai-compatible
  model: "claude-sonnet-4-20250514"
  api_key_env: "AR_LLM_API_KEY"  # nombre de la env var — la key NUNCA va en el archivo
  # base_url: "https://..."     # para proveedores compatibles-openai propios
```

Reglas del contrato:

- `scope.yaml` real **gitignored** (contiene activos del cliente); se versiona
  `scope.example.yaml`.
- Sin `authorization.reference` **la CLI se niega a iniciar la campaña**.
- `exclude` gana siempre sobre `domains`/`ips` (hard-exclusion).
- `sources` es allow-list: una fuente ausente es una fuente prohibida.

---

## 6. Capa 2 — Motor de políticas

### 6.1 Enforcement en tres puntos

| Punto | Qué valida | Aplica a |
|---|---|---|
| **Pre-flight** | El target-list completo antes de invocar cualquier binario externo; los flags de rate del propio binario se fijan aquí | Wrappers (Capa 3) y herramientas activas (Capa 5) |
| **Egress nativo** | Cada conexión la abre el propio motor tras validar scope, rate y riesgo | Módulos nativos y herramientas HTTP propias — choke point literal |
| **Persistencia** | La DB marca assets fuera de alcance como `OUT_OF_SCOPE` (constan en el reporte de exclusiones, jamás accionables) | Todo hallazgo entrante |

### 6.2 Clasificación de riesgo

| Nivel | Definición | Ejemplos | Gate |
|---|---|---|---|
| `PASSIVE` | Cero paquetes hacia la infraestructura del target; solo fuentes terceras | consulta crt.sh, lookup en NVD (`check_cve_details`) | Ninguno (si la fuente está en `sources`) |
| `LOW_IMPACT` | Requests normales hacia el target (lo que hace un navegador) | `http_request`, `fetch_js_and_extract_routes`, DNS lookup contra NS autoritativo | Rate limiter |
| `INTRUSIVE` | Interacción que un usuario legítimo no haría; puede alarmar o cargar el entorno | port scan (naabu), content discovery (fuerza de rutas) | **Approval gate**: pausa el hilo, cola en la CLI, `y/n` del operador; toda decisión queda auditada |

Por defecto la campaña arranca `PASSIVE`+`LOW_IMPACT`; `INTRUSIVE` solo si el
RoE lo habilita **y** el operador aprueba cada uso.

### 6.3 Rate limiting

Token bucket doble (global de campaña + por host) con jitter entre requests
y concurrencia por módulo acotada. El límite existe por **estabilidad del
entorno del cliente** y por el **perfil de ruido acordado** — ver §1.

---

## 7. Capa 4 — Almacén de estado

SQLite con esquema versionado. Las 8 entidades de la propuesta se unifican en
un mini-grafo relacional, más pragmático para el MVP:

| Tabla | Rol |
|---|---|
| `campaigns` | Una por engagement: hash del scope, `authorization.reference`, ventana, estado |
| `assets` | Nodo unificado: `kind` (domain, subdomain, ip, web_service, endpoint, tech), `value` normalizado, `state`, `source`, atributos JSON |
| `asset_links` | Aristas tipadas: `resolves_to`, `served_by`, `belongs_to`, `uses_tech`… |
| `observations` | Hallazgos crudos normalizados de la Capa 3 (antes de deduplicar) |
| `hypotheses` | Conjetura de un agente o del operador: `asset_id`, razonamiento, score de interés |
| `findings` | Hipótesis promovida con evidencia y severidad |
| `evidence` | Request/response inmutable vinculada a una acción (§11) |
| `approvals` | Gate INTRUSIVE pendiente/resuelto: tool, target, quién aprobó |
| `request_log` | Auditoría universal: **cada** request con actor, herramienta, target, resultado |

### Máquina de estados del asset

```
 DISCOVERED ──▶ TRIAGED ──▶ INVESTIGATING ──▶ VALIDATED
     │             │              │
     │             └──▶ DISCARDED ◀┘
     └──▶ OUT_OF_SCOPE   (terminal, set en persistencia — nunca accionable)
```

`DISCOVERED → TRIAGED` lo marca el pipeline o un agente de triaje;
`INVESTIGATING` lo reservan los especialistas (evita doble trabajo);
`VALIDATED/DISCARDED` cierran el ciclo. La campaña se pausa/reanuda con este
estado intacto.

---

## 8. Capa 3 — Pipeline determinista

Wrappers de herramientas probadas + módulos nativos, ejecutando concurrente
y escribiendo **solo** vía el ETL normalizador hacia la Capa 4.

| Módulo | Tipo | Riesgo | Qué produce |
|---|---|---|---|
| `ct-subdomains` | nativo (crt.sh JSON) | PASSIVE | subdominios desde Certificate Transparency |
| `subfinder` | wrapper | PASSIVE* | subdominios adicionales (*pre-flight scope; sus sockets son suyos) |
| `http-probe` | nativo | LOW_IMPACT | por subdominio: status, título, server, tecnologías (headers), redirecciones |
| `js-routes` | nativo | LOW_IMPACT | rutas/endpoints extraídos de assets JS |
| `dnsx` | wrapper | LOW_IMPACT | resolución y registros DNS |
| `naabu` | wrapper | **INTRUSIVE** | port scan — solo con RoE + approval por corrida |
| `katana` | wrapper | **INTRUSIVE** | crawling — igual que naabu |

ETL: parseo de salidas JSON → deduplicación (mismo hash de respuesta HTTP =
un solo asset con clones referenciados) → upsert a `assets`/`observations` con
`source` y estado inicial `DISCOVERED` (o `OUT_OF_SCOPE` si aplica).

---

## 9. Capa 5 — Toolbox tipada

El catálogo **cerrado** que ven los agentes (y la CLI). Cada función valida
en el policy engine antes de tocar nada. Firmas orientativas del MVP:

```go
// Lectura sobre la Capa 4 (sin red)
get_unexplored_assets(kind string, limit int)
get_asset_details(id string)
search_by_tech(tech string)          // "Spring Boot", "Swagger", versiones viejas…

// Inspección activa de bajo impacto (egress por el policy engine)
http_request(method, url string, headers map[string]string) → status, headers, body(ref)
fetch_cert_names(domain string)      // PASSIVE: nombres en el cert TLS del target
dns_lookup(name, qtype string)
fetch_js_and_extract_routes(url string)

// Terceros (gobernados por sources allow-list)
check_cve_details(cveID string)     // NVD: descripción/versión afectada — solo datos

// Registro en la Capa 4
save_hypothesis(assetID int, reasoning string, score float64)
promote_to_finding(assetID int, evidenceRefs []string, severity string)
request_approval(tool, target string, reason string)  // para INTRUSIVE
```

MCP llega después como segundo consumidor del mismo catálogo; el MVP usa
function calling nativo del proveedor.

---

## 10. Capa 6 — Agentes

Opcionales, con presupuestos duros y **jamás autoridad de scope**:

- **Agente de triaje (orquestador)**: consulta `get_unexplored_assets` +
  anomalías (paneles admin, Swagger expuestos, entornos dev/qa, versiones
  viejas), asigna score y crea tareas acotadas.
- **Especialistas (bucle ReAct)**: una tarea por hipótesis ("investiga
  api-dev.target.com: expone /v2/api-docs"), máx **8 pasos** y presupuesto de
  tokens por hipótesis; guardan evidencia y promueven (o descartan) vía la
  Capa 5. Cada paso queda en `request_log` con el razonamiento.

Sin `llm:` en `scope.yaml`, la CLI ofrece el mismo triaje manual
(`recon triage` lista, filtra y deja promover hipótesis a mano).

---

## 11. Evidencia y auditoría

Cada request de la campaña —humana, módulo o agente— produce una línea
inmutable en `request_log`:

```json
{"ts":"…","actor":"agent:triage","tool":"http_request","target":"https://api-dev.example.com/v2/api-docs","risk":"LOW_IMPACT","scope_verdict":"IN","approved_by":null,"result":"200","evidence_ref":"ev:8f21","campaign":"c-01"}
```

Los INTRUSIVE llevan además su entrada en `approvals` con quién aprobó y
cuándo. El reporte (§12) se reconstruye **íntegramente** desde este log —
si el cliente disputa una acción, la respuesta está a una consulta.

---

## 12. Salida: reporte del engagement

`recon report --campaign c-01 [--format md|json]` genera:

1. **Resumen de alcance** — qué se testeo, qué quedó `OUT_OF_SCOPE` y por qué.
2. **Inventario validado** — assets por estado y severidad.
3. **Rutas priorizadas hacia acceso inicial** — cada finding con su evidencia
   exacta (request/response, cabeceras, endpoint) y la hipótesis que lo originó.
4. **Registro completo de acciones** — la columna vertebral de accountability.

---

## 13. Estructura del repositorio

```
Agentic-Recon/
├── README.md
├── AGENTS.md                  # contrato del repo (líneas de uso, gates)
├── go.mod / go.sum
├── Makefile
├── scope.example.yaml         # plantilla del contrato (el real es gitignored)
├── .gitignore                 # scope.yaml, *.db, claves, logs
├── cmd/recon/main.go          # CLI: init/run/triage/approve/report
└── internal/
    ├── policy/                # scope, rate+jitter, riesgo, approval, audit
    │   ├── scope.go           # parseo+validación del contrato
    │   ├── engine.go          # el punto por el que TODO pasa
    │   └── ratelimit.go
    ├── store/                 # SQLite: schema, repos, máquina de estados
    ├── pipeline/              # módulos nativos + wrappers con pre-flight
    ├── toolbox/               # catálogo tipado (consumido por CLI y agentes)
    ├── agent/                 # cliente LLM REST + triaje/especialistas + budgets
    └── report/                # export md/json desde la DB
```

---

## 14. Roadmap

Siguiendo el orden correcto: **Capas 2, 3, 4 primero; agentes encima de datos
reales**. Sin LLM hasta R5.

| Fase | Entregable | Criterio de done |
|---|---|---|
| **R0** | Esqueleto: `go.mod`, `Makefile`, `.gitignore`, CI, `AGENTS.md` | Gates en verde desde el primer commit |
| **R1** | Policy engine: `scope.yaml` parse + validación, rate limiter, clasificador de riesgo, `request_log` | Ninguna función de red nativa existe fuera del engine (test: todo egress pasa por un hook auditable); campaña sin `authorization.reference` se niega a arrancar |
| **R2** | Store: schema SQLite + máquina de estados + evidencia | Campaña pausable/reanudable; asset out-of-scope persiste como `OUT_OF_SCOPE` y ninguna herramienta lo devuelve |
| **R3** | Pipeline pasivo: `ct-subdomains` + `http-probe` nativos + triaje manual en CLI | Campaña contra un dominio propio produce assets triaged sin salir de scope (verificado por el log) |
| **R4** | Toolbox + approval gate: catálogo tipado, `http_request`/`fetch_js`, wrappers con pre-flight | Un intento INTRUSIVE pausa la campaña y requiere `y/n` auditado |
| **R5** | Agentes: cliente LLM REST (stdlib), triaje + especialistas con presupuestos | Una hipótesis promovida a finding con evidencia y presupuesto acotado; idéntico resultado reproducible en triaje manual |
| **R6** | Reporte: export md/json desde la DB | El reporte reproduce la campaña completa desde el log |

---

## 15. Qué no se construirá

- Explotación de vulnerabilidades o pruebas de concepto de exploit.
- Ataques de credenciales (spraying, stuffing, brute-force).
- Auto-propagación o scanning de redes no incluidas en el scope.
- Mecanismos de evasión diseñados para ocultar actividad del dueño
  legítimo del sistema. El "perfil de ruido" es un parámetro del RoE, no una
  feature de ocultamiento.
- Los wrappers se limitan a herramientas de reconocimiento estándar y
  abiertas; el catálogo de la Capa 5 es cerrado por diseño.

## 16. Uso responsable

Solo sobre activos propios, laboratorios/CTF, o engagements con autorización
escrita. El `scope.yaml` con `authorization.reference` es la materialización
de ese contrato; el policy engine su enforcement técnico. Si te falta la
autorización por escrito, la respuesta es no ejecutar — no ampliar el scope
por tu cuenta.

Proyecto hermano de `ReverseShell`: este cubre la fase pre-acceso; aquel la
post-acceso. Ambos comparten la misma disciplina: scope primero, todo
auditado, cero ocultamiento.
