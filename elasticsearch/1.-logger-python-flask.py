from flask import Flask, request, g
from time import time
from elasticsearch import Elasticsearch
import uuid
from datetime import datetime

app = Flask(__name__)
es = Elasticsearch("http://localhost:9200")
INDEX_LOGS = "logs_usuarios"

# Middleware para tiempo de ejecución
@app.before_request
def antes_de_request():
    g.inicio = time()

@app.after_request
def despues_de_request(response):
    tiempo = int((time() - g.inicio) * 1000)

    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
        "tiempo_respuesta_ms": tiempo
    }

    es.index(index=INDEX_LOGS, body=log)
    return response

# Ejemplo de endpoint
@app.route("/api/datos", methods=["GET"])
def consultar_datos():
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
        "tiempo_respuesta_ms": tiempo
    }

if __name__ == "__main__":
    app.run(debug=True)
