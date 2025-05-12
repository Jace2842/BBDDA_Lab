
from flask import Flask, request, jsonify
import psycopg2

app = Flask(__name__)

def connect_db():
    return psycopg2.connect(dbname="gisdb", user="postgres", password="password", host="db")

@app.route('/servicios')
def obtener_servicios():
    lat = request.args.get('lat')
    lon = request.args.get('lon')
    radio = request.args.get('radio', 3000)
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT name, type, ST_AsGeoJSON(geom)
        FROM services
        WHERE ST_DWithin(geom::geography, ST_MakePoint(%s, %s)::geography, %s)
    """, (lon, lat, radio))
    servicios = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(servicios)

@app.route('/ruta')
def obtener_ruta():
    usuario_id = request.args.get('usuario_id')
    localizacion_id = request.args.get('localizacion_id')
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT seq, node, edge, cost, ST_AsGeoJSON(geom) as geojson
        FROM pgr_dijkstra(
            'SELECT id, source, target, cost FROM ways', %s, %s, false
        ) JOIN ways ON edge = id
    """, (usuario_id, localizacion_id))
    ruta = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(ruta)

if __name__ == '__main__':
    app.run(debug=True)
