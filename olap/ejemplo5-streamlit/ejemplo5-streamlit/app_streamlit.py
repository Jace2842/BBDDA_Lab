import streamlit as st
import psycopg2
import pandas as pd

# Título
st.title("Resumen de Calificaciones")

# Conexión PostgreSQL
conn = psycopg2.connect(
    dbname="mi_base_de_datos",
    user="mi_usuario",
    password="mi_contraseña",
    host="localhost"
)

# Consulta con columna calculada y CASE
query = """
SELECT 
    e.nombre,
    ROUND(AVG(ev.nota), 2) AS promedio,
    CASE
        WHEN AVG(ev.nota) >= 9 THEN 'Sobresaliente'
        WHEN AVG(ev.nota) >= 7 THEN 'Notable'
        WHEN AVG(ev.nota) >= 5 THEN 'Aprobado'
        ELSE 'Suspendido'
    END AS calificacion_textual
FROM estudiantes e
JOIN matriculaciones m ON e.id = m.estudiante_id
JOIN evaluaciones ev ON ev.matriculacion_id = m.id
GROUP BY e.id, e.nombre
ORDER BY promedio DESC;
"""

df = pd.read_sql(query, conn)

# Mostrar tabla
st.dataframe(df)

# Filtro por calificación
filtro = st.selectbox("Filtrar por calificación", ["Todos"] + df["calificacion_textual"].unique().tolist())

if filtro != "Todos":
    df = df[df["calificacion_textual"] == filtro]

st.bar_chart(df.set_index("nombre")["promedio"])
