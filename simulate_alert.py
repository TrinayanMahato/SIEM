import requests
import json
import time
from datetime import datetime, timezone

def seed_elasticsearch(ip_address, host_name):
    print("Seeding Elasticsearch with mock data...")
    es_url = "http://localhost:9200/logstash-mock/_bulk"
    
    # We will insert 5 failed HTTP 403 logs for this IP
    bulk_data = ""
    for i in range(5):
        action = {"index": {"_index": "logstash-mock"}}
        doc = {
            "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": {"ip": ip_address},
            "host": {"name": host_name},
            "http": {"response": {"status_code": 403}},
            "url": {"path": "/admin/login"},
            "event": {"dataset": "nginx.access"}
        }
        bulk_data += json.dumps(action) + "\n" + json.dumps(doc) + "\n"
        
    try:
        # Insert data
        requests.post(es_url, headers={"Content-Type": "application/x-ndjson"}, data=bulk_data)
        # Force refresh so it's immediately searchable
        requests.post("http://localhost:9200/logstash-mock/_refresh")
        print("Mock data seeded and index refreshed successfully.")
    except Exception as e:
        print(f"Failed to seed Elasticsearch: {e}")

def simulate_alert():
    url = "http://127.0.0.1:8000/webhook"
    ip_address = "192.168.1.100"
    host_name = "web-server-01"
    
    # First, seed the DB so Gemini has logs to analyze
    seed_elasticsearch(ip_address, host_name)
    
    # Mock payload for HTTP Error Spike
    payload = {
        "rule_name": "HTTP Error Spike",
        "http.response.status_code": "403",
        "source.ip": ip_address,
        "host.name": host_name,
        "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "message": "Detected a spike in 403 errors"
    }

    print(f"\nSending webhook to {url}...")
    try:
        response = requests.post(url, json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Failed to connect to server: {e}")

if __name__ == "__main__":
    simulate_alert()
