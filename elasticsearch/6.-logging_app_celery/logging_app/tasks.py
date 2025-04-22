from celery import Celery
from elasticsearch import Elasticsearch
from datetime import datetime

app = Celery('tasks')
app.config_from_object('celeryconfig')

es = Elasticsearch("http://localhost:9200")
INDEX = "logs_usuarios"

@app.task
def guardar_log(log):
    log["timestamp"] = datetime.utcnow().isoformat()
    try:
        es.index(index=INDEX, body=log)
    except Exception as e:
        print(f"Error al guardar log: {e}")