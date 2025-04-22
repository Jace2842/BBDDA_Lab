from elasticsearch import Elasticsearch
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

es = Elasticsearch("http://localhost:9200")
INDEX = "logs_usuarios"

# 1. Obtener todos los logs
def obtener_logs():
    query = {
        "size": 10000,
        "_source": ["timestamp", "funcion", "tiempo_respuesta_ms"],
        "query": {
            "match_all": {}
        }
    }
    res = es.search(index=INDEX, body=query, scroll="2m")
    logs = [hit["_source"] for hit in res["hits"]["hits"]]
    return logs

# 2. Analizar y graficar
def analizar_logs():
    logs = obtener_logs()
    df = pd.DataFrame(logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["fecha"] = df["timestamp"].dt.date

    # Funciones más usadas
    top_funcs = df["funcion"].value_counts().head(10)
    top_funcs.plot(kind="barh", title="Funciones más usadas")
    plt.tight_layout()
    plt.show()

    # Tiempo medio por función
    tiempos = df.groupby("funcion")["tiempo_respuesta_ms"].mean().sort_values()
    tiempos.plot(kind="bar", title="Tiempo promedio por función (ms)")
    plt.tight_layout()
    plt.show()

    # Tráfico por día
    diario = df.groupby("fecha").size()
    diario.plot(title="Número de peticiones por día")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    analizar_logs()
