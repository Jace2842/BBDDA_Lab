SELECT 
    e.id AS estudiante_id,
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
