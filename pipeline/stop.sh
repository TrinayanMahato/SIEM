#!/bin/bash
# Stop everything start.sh launched.
echo "Shutting down SOC pipeline..."

brew services stop kafka
pkill -f "vector --config"
pkill -f "logstash -f"
pkill -f "elasticsearch"

echo "All services stopped."
