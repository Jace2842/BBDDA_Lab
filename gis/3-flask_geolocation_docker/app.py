from flask import Flask, request, render_template_string, jsonify
from sqlalchemy import create_engine, text
from geoalchemy2 import WKTElement

app = Flask(__name__)

DATABASE_URL = "postgresql+psycopg2://usuario:contraseña@db:5432/tu_basededatos"
engine = create_engine(DATABASE_URL)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Enviar Geolocalización</title>
</head>
<body>
    <h1>Enviar Geolocalización</h1>
    <button onclick="enviarUbicacion()">Enviar mi ubicación</button>

    <script>
    function enviarUbicacion() {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(function(position) {
                fetch('/guardar_ubicacion', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        latitud: position.coords.latitude,
                        longitud: position.coords.longitude
                    })
                }).then(response => response.json())
                  .then(data => alert(data.mensaje))
                  .catch(error => console.error('Error:', error));
            });
        } else {
            alert('Geolocalización no soportada por este navegador.');
        }
    }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_PAGE)

@app.route('/guardar_ubicacion', methods=['POST'])
def guardar_ubicacion():
    data = request.get_json()
    lat = data['latitud']
    lon = data['longitud']

    with engine.connect() as conn:
        conn.execute(
            text("INSERT INTO ubicaciones (geom) VALUES (ST_SetSRID(ST_MakePoint(:lon, :lat), 4326))"),
            {"lon": lon, "lat": lat}
        )

    return jsonify({"mensaje": "Ubicación guardada correctamente."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)