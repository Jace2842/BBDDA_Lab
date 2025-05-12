import psycopg2
import pandas as pd

conn = psycopg2.connect(
    dbname="BBDDA",
    user="jesus",
    password="28425531",
    host="localhost"
)

query = """
SELECT * FROM crosstab(
    $$
    SELECT e.nombre, a.nombre AS asignatura, ev.nota
    FROM estudiantes e
    JOIN matriculaciones m ON e.id = m.estudiante_id
    JOIN asignaturas a ON a.id = m.asignatura_id
    JOIN evaluaciones ev ON ev.matriculacion_id = m.id
    ORDER BY 1, 2
    $$,
    $$ SELECT nombre FROM asignaturas ORDER BY id $$
) AS ct (
    estudiante TEXT,
    matematicas NUMERIC,
    historia NUMERIC,
    fisica NUMERIC
)
"""

df = pd.read_sql(query, conn)
print(df)
