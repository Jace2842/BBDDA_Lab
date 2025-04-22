from elasticsearch import Elasticsearch
from tabulate import tabulate

es = Elasticsearch("http://localhost:9200")

query_match = {'query': {'match': {'departamento': 'Ventas'}}}
result = es.search(index='empleados', body=query_match)

# Formatear los resultados de la búsqueda con tabulate
headers = ["Nombre", "Edad", "Departamento"]
rows = []
for hit in result['hits']['hits']:
    nombre = hit['_source']['nombre']
    edad = hit['_source']['edad']
    departamento = hit['_source']['departamento']
    rows.append([nombre, edad, departamento])

print(tabulate(rows, headers=headers))