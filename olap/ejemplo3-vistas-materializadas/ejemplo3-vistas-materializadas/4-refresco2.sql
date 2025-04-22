-- 1. Edita tu postgresql.conf:
--shared_preload_libraries = 'pg_cron'
--------------------------------------------------------------
-- 2. Crear la extensión (solo una vez):
CREATE EXTENSION IF NOT EXISTS pg_cron;
--------------------------------------------------------------
-- 3. Programar refresco 
SELECT cron.schedule(
  'refrescar_resumen_cada_hora',
  '0 * * * *',  -- Cada hora en punto
  'REFRESH MATERIALIZED VIEW resumen_notas_estudiantes'
);

