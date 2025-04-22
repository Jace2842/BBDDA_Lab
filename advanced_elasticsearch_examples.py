
from elasticsearch_Lab import Elasticsearch

es = Elasticsearch("http://localhost:9200")

# Crear índices
es.indices.create(index='empleados')
es.indices.create(index='departamentos')

# Insertar documentos múltiples
es.index(index='empleados', id=1, document={'nombre':'Ana','edad':27,'departamento':'Ventas'})
es.index(index='empleados', id=2, document={'nombre':'Luis','edad':32,'departamento':'TI'})
es.index(index='empleados', id=3, document={'nombre':'Maria','edad':29,'departamento':'Ventas'})
es.index(index='departamentos', id=1, document={'departamento':'Ventas','ubicacion':'Edificio A'})
es.index(index='departamentos', id=2, document={'departamento':'TI','ubicacion':'Edificio B'})

# Actualizar documento
es.update(index='empleados', id=1, doc={'doc':{'edad':28}})

# Consulta avanzada match
query_match = {'query':{'match':{'departamento':'Ventas'}}}
print(es.search(index='empleados', body=query_match))

# Consulta avanzada term
query_term = {'query':{'term':{'edad':32}}}
print(es.search(index='empleados', body=query_term))

# Consulta avanzada range
query_range = {'query':{'range':{'edad':{'gte':28,'lte':35}}}}
print(es.search(index='empleados', body=query_range))

# Consulta wildcard
query_wildcard = {'query':{'wildcard':{'nombre':'L*'}}}
print(es.search(index='empleados', body=query_wildcard))

# Agregación por departamentos
agg_query = {'size':0,'aggs':{'por_departamento':{'terms':{'field':'departamento.keyword'}}}}
print(es.search(index='empleados', body=agg_query))
