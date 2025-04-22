from elasticsearch import Elasticsearch
import pandas as pd

es = Elasticsearch("http://localhost:9200")
INDEX = "logs_usuarios"

def detectar_usuarios_lentos(umbral_ms=1000):
    query = {
        "size": 10000,
        "_source": ["usuario_id", "funcion", "tiempo_respuesta_ms"],
        "query": {
            "range": {
                "tiempo_respuesta_ms": {"gt": umbral_ms}
            }
        }
    }
    res = es.search(index=INDEX, body=query, scroll="2m")
    data = [hit["_source"] for hit in res["hits"]["hits"]]
    df = pd.DataFrame(data)

    if df.empty:
        print("No se detectaron usuarios lentos.")
    else:
        resumen = df.groupby("usuario_id").size().sort_values(ascending=False)
        print("Usuarios con más respuestas lentas:\n", resumen)

if __name__ == "__main__":
    detectar_usuarios_lentos(umbral_ms=1500)
