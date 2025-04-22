-- Refrescar la Vista Materializada

REFRESH MATERIALIZED VIEW resumen_notas_estudiantes;
-- ⚠️ Opcional: Para permitir acceso concurrente mientras se actualiza:
REFRESH MATERIALIZED VIEW CONCURRENTLY resumen_notas_estudiantes;
--
SELECT * FROM resumen_notas_estudiantes WHERE promedio_nota >= 7.5;
