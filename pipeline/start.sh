#!/bin/bash
# Start the SOC log pipeline: Kafka → Elasticsearch → Logstash → Vector.
# Run the FastAPI SIEM app and ElastAlert separately (see pipeline/README.md).
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$DIR/logs"
mkdir -p "$LOGS"

echo "Starting SOC pipeline..."

# 1. Kafka
echo "  -> Kafka"
brew services start kafka

# 2. Elasticsearch
echo "  -> Elasticsearch"
if [ -z "${ES_JAVA_HOME:-}" ]; then
  for candidate in \
    "$(/usr/libexec/java_home -v 21 2>/dev/null)" \
    "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
    "/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"; do
    if [ -n "$candidate" ] && [ -d "$candidate" ]; then export ES_JAVA_HOME="$candidate"; break; fi
  done
fi
if [ -z "${ES_JAVA_HOME:-}" ]; then
  echo "     ES_JAVA_HOME not set and no JDK 21 found — set it manually." >&2
else
  echo "     using JDK: $ES_JAVA_HOME"
fi
nohup elasticsearch > "$LOGS/elasticsearch.log" 2>&1 &

# Wait for Elasticsearch to answer before starting anything that depends on it
echo "     waiting for Elasticsearch on :9200"
for i in $(seq 1 60); do
  if curl -s -o /dev/null http://127.0.0.1:9200; then echo "     up after ${i}s"; break; fi
  sleep 1
  [ "$i" = "60" ] && echo "     still not up after 60s — continuing anyway" >&2
done

# 3. Logstash
echo "  -> Logstash"
nohup logstash -f "$DIR/logstash.conf" > "$LOGS/logstash.log" 2>&1 &

# 4. Vector
echo "  -> Vector"
nohup vector --config "$DIR/vector.toml" > "$LOGS/vector.log" 2>&1 &

echo "Pipeline running. Logs: $LOGS/"
