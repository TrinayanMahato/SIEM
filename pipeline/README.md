# SOC Log Pipeline

Everything upstream of the SIEM app: collection, transport, parsing, storage and alerting.
The SIEM service in the repository root is the last stage — it receives a webhook from
ElastAlert and decides what to do about it.

---

## Data Flow

```
┌──────────────────────────────────────────────────────────────┐
│  macOS unified log                                           │
│    predicate: process == sshd | sudo | login                 │
└───────────────────────────┬──────────────────────────────────┘
                            │  filtered at the source
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  VECTOR            vector.toml                               │
│    exec → remap (rename timestamp → mac_timestamp,           │
│                  tag event_source) → kafka sink              │
└───────────────────────────┬──────────────────────────────────┘
                            │  topic: soc-raw-logs
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  KAFKA             127.0.0.1:9092                            │
│    decouples collection from parsing — the shipper keeps     │
│    running if Logstash or Elasticsearch is restarted         │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  LOGSTASH          logstash.conf                             │
│    kafka input → json filter (message → web) → es output     │
└───────────────────────────┬──────────────────────────────────┘
                            │  index: soc-logs-YYYY.MM.dd
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  ELASTICSEARCH     127.0.0.1:9200                            │
└───────────────────────────┬──────────────────────────────────┘
                            │  queried every minute
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  ELASTALERT 2      elastalert/config.yaml + rules/           │
│    SSH Failed Logins · Multiple Failed Login Attempts        │
│    HTTP Error Spike                                          │
└───────────────────────────┬──────────────────────────────────┘
                            │  POST http://127.0.0.1:8000/webhook
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  SIEM APP          ../main.py                                │
│    persist → enrich from Elasticsearch → Gemini verdict      │
│    → whitelist → enforce or ask an analyst                   │
└──────────────────────────────────────────────────────────────┘
```

### Why Kafka sits in the middle

Vector could write to Elasticsearch directly. Kafka buys two things: the shipper never
blocks on a slow or restarting consumer, and the raw stream can be replayed into a second
consumer later without re-collecting anything from the host.

### Why the timestamp is renamed

The macOS unified log emits a `timestamp` field whose format collides with the existing
mapping in the `soc-logs-*` index. The Vector transform moves it to `mac_timestamp` so
Elasticsearch assigns the document its own `@timestamp` and indexing does not fail.

---

## Files

| File | Stage | Purpose |
| :--- | :--- | :--- |
| `vector.toml` | Shipper | Source predicate, field transform, Kafka sink |
| `logstash.conf` | Parser | Kafka consumer, JSON filter, Elasticsearch output |
| `elastalert/config.yaml` | Alerting | Query interval, ES connection, writeback index |
| `elastalert/rules/*.yaml` | Alerting | The three detection rules |
| `sigma/*.yml` | Detection | Sigma-format rule kept as a source of truth |
| `start.sh` / `stop.sh` | Ops | Bring the backend up and down |

---

## Rule Names Are a Contract

`services/alert_handlers.py` dispatches on the `rule_name` field in the webhook body:

| Rule `name:` | Handler |
| :--- | :--- |
| `SSH Failed Logins` | `handle_ssh_failed_logins()` |
| `Multiple Failed Login Attempts` | `handle_multiple_failed_login_attempts()` |
| `HTTP Error Spike` | `handle_http_error_spike()` |

Anything else falls through to `handle_unknown_rule()`. **Renaming a rule silently changes
which handler runs**, so the `name:` in each YAML file and the string in the dispatcher must
be changed together.

Each rule sends `rule_name` via `http_post_static_payload`, because ElastAlert does not
include the rule name in the POST body automatically — only the matched document's fields.

---

## Prerequisites

```bash
brew install kafka elasticsearch logstash vector
brew install openjdk@21
```

ElastAlert 2 runs in its own virtualenv:

```bash
python3 -m venv elastalert-env
source elastalert-env/bin/activate
pip install elastalert2
```

---

## Running

Start the backend (Kafka, Elasticsearch, Logstash, Vector):

```bash
./start.sh
```

`start.sh` resolves its own directory, so it works from any checkout location, and it polls
Elasticsearch until it answers rather than sleeping a fixed interval.

Then start the SIEM app from the repository root:

```bash
uvicorn main:app --reload
```

And ElastAlert, from this directory:

```bash
source elastalert-env/bin/activate
elastalert --config elastalert/config.yaml --verbose
```

Shut everything down:

```bash
./stop.sh
```

---

## Verifying the Chain

```bash
# 1. Is the topic receiving events?
kafka-console-consumer --bootstrap-server 127.0.0.1:9092 --topic soc-raw-logs --max-messages 5

# 2. Are documents landing in Elasticsearch?
curl -s 'http://127.0.0.1:9200/soc-logs-*/_count' | python3 -m json.tool

# 3. Does a rule match anything right now?
elastalert-test-rule --config elastalert/config.yaml elastalert/rules/ssh_failed_logins.yaml

# 4. Generate real SSH failures to exercise the chain
ssh nosuchuser@127.0.0.1    # repeat past the rule threshold
```

The SIEM app prints the routed rule name on receipt, so a working chain ends with
`Routing alert for rule: SSH Failed Logins` in the uvicorn terminal.

---

## Sigma Rules

`sigma/` holds rules in Sigma format as a portable source of truth. The upstream
[SigmaHQ ruleset](https://github.com/SigmaHQ/sigma) is **not** vendored here — clone it
alongside if you want the full catalogue:

```bash
git clone https://github.com/SigmaHQ/sigma.git
sigma convert -t elasticsearch -p ecs_windows sigma/suspicious_whoami_execution.yml
```
