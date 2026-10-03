import os
from elasticsearch import AsyncElasticsearch
from dotenv import load_dotenv

load_dotenv()

# Async Elasticsearch Client
es = AsyncElasticsearch(os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200"))
