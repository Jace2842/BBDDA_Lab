from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

es.index(index='logs', document={
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
        "tiempo_respuesta_ms": duracion
    })



# Agregar más departamentos al índice "departamentos"
es.index(index='departamentos', id=3, document={'departamento': 'Recursos Humanos', 'ubicacion': 'Edificio C'})
es.index(index='departamentos', id=4, document={'departamento': 'Marketing', 'ubicacion': 'Edificio D'})
es.index(index='departamentos', id=5, document={'departamento': 'Finanzas', 'ubicacion': 'Edificio E'})

print("Personas y departamentos agregados a Elasticsearch.")