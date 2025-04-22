CREATE MATERIALIZED VIEW resumen_notas_estudiantes AS
SELECT 
    e.id AS estudiante_id,
    e.nombre AS estudiante,
    ROUND(AVG(ev.nota), 2) AS promedio_nota,
    COUNT(ev.id) AS total_evaluaciones
FROM estudiantes e
JOIN matriculaciones m ON e.id = m.estudiante_id
JOIN evaluaciones ev ON ev.matriculacion_id = m.id
GROUP BY e.id, e.nombre
ORDER BY promedio_nota DESC;
