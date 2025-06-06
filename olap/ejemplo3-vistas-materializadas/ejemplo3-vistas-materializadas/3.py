import psycopg2
import pandas as pd

conn = psycopg2.connect(
    dbname="BBDDA",
    user="jesus",
    password="28425531",
    host="localhost"
)

# Consulta a la vista materializada
query = "SELECT * FROM resumen_notas_estudiantes ORDER BY promedio_nota DESC"

df = pd.read_sql(query, conn)
print(df)

# Refrescar la vista (requiere permisos)
with conn.cursor() as cur:
    cur.execute("REFRESH MATERIALIZED VIEW resumen_notas_estudiantes;")
    conn.commit()
