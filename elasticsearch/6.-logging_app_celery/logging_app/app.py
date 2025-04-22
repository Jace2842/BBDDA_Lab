from flask import Flask, request, g
from time import time
import uuid
from tasks import guardar_log

app = Flask(__name__)

@app.before_request
def before_request():
    g.inicio = time()

@app.after_request
def after_request(response):
    duracion = int((time() - g.inicio) * 1000)

    log = {
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
        "tiempo_respuesta_ms": duracion
    }

    # Llama a la tarea asíncrona
    guardar_log.delay(log)

    return response

# Endpoint de ejemplo
@app.route("/api/datos", methods=["GET"])
def consultar_datos():
    return {"data": "respuesta desde Flask"}

if __name__ == "__main__":
    app.run(debug=True)