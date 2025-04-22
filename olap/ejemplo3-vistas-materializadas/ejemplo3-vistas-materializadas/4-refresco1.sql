CREATE OR REPLACE FUNCTION refrescar_resumen_notas()
RETURNS TRIGGER AS $$
BEGIN
  REFRESH MATERIALIZED VIEW resumen_notas_estudiantes;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;


CREATE TRIGGER trigger_refresco_notas
AFTER INSERT OR UPDATE OR DELETE ON evaluaciones
FOR EACH STATEMENT
EXECUTE FUNCTION refrescar_resumen_notas();
