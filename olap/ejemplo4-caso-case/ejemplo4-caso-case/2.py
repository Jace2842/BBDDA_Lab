import psycopg2
import pandas as pd

# Conexión
conn = psycopg2.connect(
    dbname="mi_base_de_datos",
    user="mi_usuario",
    password="mi_clave",
    host="localhost"
)

# Leer la vista directamente
query = "SELECT * FROM vista_calificaciones"
df = pd.read_sql(query, conn)

# Mostrar
print(df)

# Opcional: Agrupación o filtros
print("\nEstudiantes con 'Notable':")
print(df[df['calificacion_textual'] == 'Notable'])

