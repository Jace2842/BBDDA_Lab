from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

# Realiza operaciones en Elasticsearch
if es.ping():
    print("Conexión exitosa a Elasticsearch en Docker")
else:
    print("No se pudo conectar a Elasticsearch en Docker")