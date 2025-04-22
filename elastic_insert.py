from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

es.index(index='empleados', id=4, document={'nombre': 'Carlos', 'edad': 35, 'departamento': 'Recursos Humanos'})
es.index(index='empleados', id=5, document={'nombre': 'Sofia', 'edad': 28, 'departamento': 'Marketing'})
es.index(index='empleados', id=6, document={'nombre': 'Javier', 'edad': 41, 'departamento': 'Finanzas'})
es.index(index='empleados', id=7, document={'nombre': 'Laura', 'edad': 31, 'departamento': 'Recursos Humanos'})
es.index(index='empleados', id=8, document={'nombre': 'Diego', 'edad': 25, 'departamento': 'Marketing'})
es.index(index='empleados', id=9, document={'nombre': 'Elena', 'edad': 38, 'departamento': 'Finanzas'})

# Agregar más departamentos al índice "departamentos"
es.index(index='departamentos', id=3, document={'departamento': 'Recursos Humanos', 'ubicacion': 'Edificio C'})
es.index(index='departamentos', id=4, document={'departamento': 'Marketing', 'ubicacion': 'Edificio D'})
es.index(index='departamentos', id=5, document={'departamento': 'Finanzas', 'ubicacion': 'Edificio E'})

print("Personas y departamentos agregados a Elasticsearch.")