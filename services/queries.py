def get_ssh_failed_logins_query(ip_address: str) -> dict:
    """
    Returns the Elasticsearch query DSL body to fetch
    recent logs from a specific IP over the last 1 hour.
    """
    return {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"source.ip": ip_address}},
                    {"range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 100
    }


def get_physical_login_failures_query(host_name: str) -> dict:
    """
    Returns the Elasticsearch query DSL body to fetch recent authentication
    logs (PAM / auth category) for a given host over the last 1 hour,
    with aggregations on distinct users and event outcomes.
    """
    return {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name": host_name}},
                    {"range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"event.category": "authentication"}},
                                {"match": {"message": "pam_unix"}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        },
        "aggs": {
            "distinct_users": {
                "terms": {"field": "user.name.keyword", "size": 10}
            },
            "outcomes": {
                "terms": {"field": "event.outcome"}
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 50
    }


def get_privilege_escalation_query(host_name: str) -> dict:
    """
    Returns the Elasticsearch query DSL body to fetch recent sudo /
    privilege-escalation authentication logs for a host over the last 1 hour,
    with aggregations on source IPs, users and outcomes.
    """
    return {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name": host_name}},
                    {"range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}},
                    {
                        "bool": {
                            "should": [
                                {"match": {"process.name": "sudo"}},
                                {"match": {"message": "sudo"}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        },
        "aggs": {
            "source_ips": {"terms": {"field": "source.ip", "size": 10}},
            "distinct_users": {"terms": {"field": "user.name.keyword", "size": 10}},
            "outcomes": {"terms": {"field": "event.outcome"}}
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 50
    }


def get_http_4xx_errors_query(ip_address: str) -> dict:
    """
    Returns the Elasticsearch query DSL body to fetch recent HTTP 4xx
    responses for a given source IP over the last 1 hour, with aggregations
    on status codes, requested URLs, HTTP methods and user agents.
    """
    return {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"source.ip": ip_address}},
                    {"range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}},
                    {"range": {"http.response.status_code": {"gte": 400, "lte": 499}}}
                ]
            }
        },
        "aggs": {
            "status_codes": {"terms": {"field": "http.response.status_code", "size": 10}},
            "top_urls": {"terms": {"field": "url.original.keyword", "size": 25}},
            "methods": {"terms": {"field": "http.request.method", "size": 10}},
            "user_agents": {"terms": {"field": "user_agent.original.keyword", "size": 5}},
            "distinct_urls": {"cardinality": {"field": "url.original.keyword"}}
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 100
    }
