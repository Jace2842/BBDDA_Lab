from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

# Verifica si existe
if not es.indices.exists(index="empleados"):
    es.indices.create(
        index="empleados",
        body={
            "mappings": {
                "properties": {
                    "nombre": {"type": "text"},
                    "edad": {"type": "integer"},
                    "departamento": {"type": "keyword"}
                }
            }
        }
    )
    print("Índice 'empleados' creado.")
else:
    print("Ya existe el índice.")
