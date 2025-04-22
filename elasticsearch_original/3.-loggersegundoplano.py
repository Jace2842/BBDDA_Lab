from flask import Flask, request, g
from time import time
from elasticsearch import Elasticsearch
from datetime import datetime
from threading import Thread
import queue
import uuid

app = Flask(__name__)

es = Elasticsearch("http://localhost:9200")
INDEX_LOGS = "logs_usuarios"
log_queue = queue.Queue()

# --- Worker en segundo plano ---
def worker_logs():
    while True:
        log = log_queue.get()
        if log is None:
            break
        try:
            es.index(index=INDEX_LOGS, body=log)
        except Exception as e:
            print(f"Error al guardar log: {e}")
        log_queue.task_done()

thread = Thread(target=worker_logs, daemon=True)
thread.start()

# --- Middleware Flask ---
@app.before_request
def before_request():
    g.inicio = time()

@app.after_request
def after_request(response):
    duracion = int((time() - g.inicio) * 1000)
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
        "tiempo_respuesta_ms": duracion
    }
    log_queue.put(log)
    return response

# --- Endpoint de ejemplo ---
@app.route("/api/datos", methods=["GET"])
def consultar_datos():
    return {"data": "Respuesta de ejemplo"}

if __name__ == "__main__":
    app.run(debug=True)
