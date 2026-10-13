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

## Configuring Kafka

Kafka is the buffer between collection and parsing. Vector produces to it, Logstash
consumes from it, and neither has to be running for the other to work.

> **Kafka 4.x runs in KRaft mode — there is no ZooKeeper.** ZooKeeper was removed in
> Kafka 4.0. Any guide telling you to start `zookeeper-server-start` is written for 3.x and
> does not apply. Nothing should be listening on `:2181`.

### Install and start

```bash
brew install kafka
brew services start kafka
```

Homebrew formats the KRaft storage directory and generates a cluster ID on first start, so
there is no `kafka-storage format` step to run by hand.

### Broker configuration

Config lives at `/opt/homebrew/etc/kafka/server.properties` (Intel Macs:
`/usr/local/etc/kafka/`). The defaults are already correct for a single-node pipeline — the
settings that matter here:

| Setting | Value | Meaning |
| :--- | :--- | :--- |
| `process.roles` | `broker,controller` | One process is both — correct for a single node |
| `node.id` | `1` | Unique per node; only one here |
| `listeners` | `PLAINTEXT://:9092`<br>`CONTROLLER://:9093` | 9092 serves clients, 9093 is internal quorum traffic |
| `advertised.listeners` | `PLAINTEXT://localhost:9092` | The address handed back to clients — see the gotcha below |
| `log.dirs` | `/opt/homebrew/var/lib/kraft-combined-logs` | Where messages are stored on disk |
| `num.partitions` | `1` | Default for auto-created topics |
| `log.retention.hours` | `168` | Messages are deleted after 7 days |

**The `advertised.listeners` gotcha.** A client connects to `bootstrap_servers`, and the
broker replies with the address in `advertised.listeners` — the client then reconnects to
*that*. If it says `localhost` and the client is in Docker or on another machine, the
client will try to reach `localhost` on its own side and fail with a connection error that
looks like the broker is down. Set it to a reachable hostname or IP in that case.

### Creating the topic

The pipeline uses one topic, `soc-raw-logs`:

```bash
kafka-topics --bootstrap-server 127.0.0.1:9092   --create --topic soc-raw-logs   --partitions 1 --replication-factor 1
```

`--replication-factor 1` is mandatory on a single node — asking for more than the number of
brokers fails outright. One partition is right here because it preserves total ordering of
events; add partitions only when a single consumer cannot keep up, accepting that ordering
is then only guaranteed per partition.

Confirm it:

```bash
kafka-topics --bootstrap-server 127.0.0.1:9092 --describe --topic soc-raw-logs
```

```
Topic: soc-raw-logs  PartitionCount: 1  ReplicationFactor: 1
  Partition: 0  Leader: 1  Replicas: 1  Isr: 1
```

`Leader: 1` and `Isr: 1` mean the broker owns the partition and it is in sync — the topic
is ready.

### Retention

Messages are kept 7 days by default, which can be a lot of disk for a busy log stream.
Shorten it per topic without touching the broker:

```bash
# keep 24 hours
kafka-configs --bootstrap-server 127.0.0.1:9092   --alter --entity-type topics --entity-name soc-raw-logs   --add-config retention.ms=86400000
```

### Who connects where

| Component | Role | Setting |
| :--- | :--- | :--- |
| Vector | producer | `bootstrap_servers = "127.0.0.1:9092"` in `vector.toml` |
| Logstash | consumer | `bootstrap_servers => "127.0.0.1:9092"` in `logstash.conf` |

Logstash joins consumer group `logstash` and Kafka tracks its offset there, which is what
lets Logstash restart and resume where it stopped rather than replaying everything.

### Checking Kafka

```bash
# Broker up and topics present
kafka-topics --bootstrap-server 127.0.0.1:9092 --list

# Watch events arrive from Vector
kafka-console-consumer --bootstrap-server 127.0.0.1:9092 --topic soc-raw-logs --max-messages 5

# Inject a test event without Vector
echo '{"test":"hello"}' | kafka-console-producer --bootstrap-server 127.0.0.1:9092 --topic soc-raw-logs

# Is Logstash keeping up? LAG should stay near zero
kafka-consumer-groups --bootstrap-server 127.0.0.1:9092 --describe --group logstash
```

That last command is the one to reach for first when documents stop appearing in
Elasticsearch. Growing `LAG` means Logstash is behind or stopped; `LAG` at zero with no new
documents means the problem is downstream of Kafka, not in it.

### Common failures

| Symptom | Cause |
| :--- | :--- |
| `Connection to node -1 could not be established` | Broker not running — `brew services list` |
| Client connects then immediately drops | `advertised.listeners` points somewhere the client cannot reach |
| `replication factor: 2 larger than available brokers: 1` | Only one broker exists; use `--replication-factor 1` |
| Topic missing after restart | `log.dirs` was cleared; recreate the topic |
| Logstash reprocesses everything | Consumer group offsets reset — check `--describe --group logstash` |

### Resetting

To wipe the stream and start clean:

```bash
brew services stop kafka
rm -rf /opt/homebrew/var/lib/kraft-combined-logs
brew services start kafka
kafka-topics --bootstrap-server 127.0.0.1:9092 --create --topic soc-raw-logs --partitions 1 --replication-factor 1
```

This deletes every buffered message and all consumer offsets.

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

Kafka needs its topic created before anything can flow — see
[Configuring Kafka](#configuring-kafka).

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
