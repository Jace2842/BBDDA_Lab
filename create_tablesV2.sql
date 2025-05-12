DROP TABLE IF EXISTS course_alumn_rel CASCADE;
DROP TABLE IF EXISTS alumn CASCADE;
DROP TABLE IF EXISTS course CASCADE;
DROP TABLE IF EXISTS teacher CASCADE;

-- Creación de la tabla 'alumn'
CREATE TABLE alumn (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    street_address VARCHAR(255) NOT NULL,
    birthday DATE,
    lastmodified TIMESTAMP DEFAULT NOW(),
    saldo NUMERIC(10,2) NOT NULL DEFAULT 0,
    nota VARCHAR(255),  -- Añadido según la descripción
    hash_password TEXT   -- Añadido según la descripción
);

-- Índices para la tabla 'alumn'
CREATE INDEX alumn_first_name_idx ON alumn USING GIN (first_name gin_trgm_ops);
CREATE INDEX alumn_last_name_idx ON alumn USING GIN (last_name gin_trgm_ops);
CREATE INDEX alumn_street_address_idx ON alumn USING GIN (street_address gin_trgm_ops);
CREATE INDEX alumn_birthday_idx ON alumn (birthday);


-- Creación de la tabla 'teacher'
CREATE TABLE teacher (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    lastmodified TIMESTAMP DEFAULT NOW(),
    nota TEXT,       -- Añadido según la descripción
    hash_password TEXT  -- Añadido según la descripción
);

-- Índice para la tabla 'teacher'
CREATE INDEX teacher_name_idx ON teacher USING GIN (name gin_trgm_ops);


-- Creación de la tabla 'course'
CREATE TABLE course (
    id SERIAL PRIMARY KEY,
    teacher_id INTEGER REFERENCES teacher (id) ON DELETE RESTRICT,
    name VARCHAR(255) NOT NULL,
    lastmodified TIMESTAMP DEFAULT NOW(),
    precio NUMERIC(10,2),
    cupo_disponible INTEGER DEFAULT 50,
    nombre JSONB      -- Añadido según la descripción
);

-- Índices para la tabla 'course'
CREATE INDEX course_name_idx ON course USING GIN (name gin_trgm_ops);
CREATE INDEX course_teacher_id_idx ON course (teacher_id);


-- Creación de la tabla de relación 'course_alumn_rel'
CREATE TABLE course_alumn_rel (
    alumn_id INTEGER NOT NULL REFERENCES alumn (id) ON UPDATE CASCADE ON DELETE CASCADE,
    course_id INTEGER NOT NULL REFERENCES course (id) ON UPDATE CASCADE ON DELETE CASCADE,
    PRIMARY KEY (alumn_id, course_id),
    lastmodified TIMESTAMP DEFAULT NOW(),  -- Añadido según la descripción
    calificacion NUMERIC(10,2)
);

-- Índices para la tabla 'course_alumn_rel'
CREATE INDEX course_alumn_rel_alumn_id_idx ON course_alumn_rel (alumn_id);
CREATE INDEX course_alumn_rel_course_id_idx ON course_alumn_rel (course_id);

-- Creación de tablas foráneas (usando postgres_fdw)
--
--  NOTA IMPORTANTE: La creación de tablas foráneas requiere que la extensión
--  postgres_fdw esté instalada y configurada.  Este script asume que ya lo está.
--  También asume que ya se ha creado un servidor remoto y un mapeo de usuario.
--  Debes adaptar los nombres del servidor, esquema y tabla a tu entorno.
--
--  Ejemplo de configuración de postgres_fdw (NO EJECUTAR DIRECTAMENTE, ADAPTAR):
--
--  CREATE EXTENSION IF NOT EXISTS postgres_fdw;
--  CREATE SERVER mi_servidor_remoto
--      FOREIGN DATA WRAPPER postgres_fdw
--      OPTIONS (host 'host_remoto', port 'puerto_remoto', dbname 'nombre_db_remota');
--  CREATE USER MAPPING FOR usuario_local
--      SERVER mi_servidor_remoto
--      OPTIONS (user 'usuario_remoto', password 'contraseña_remota');


CREATE FOREIGN TABLE public.alumn_audit (
    "operation" CHAR(1),
    "stamp" TIMESTAMP,
    "userid" VARCHAR,
    "id" INTEGER,
    "first_name" VARCHAR(255),
    "last_name" VARCHAR(255),
    "street_address" VARCHAR(255)
)
SERVER mi_servidor_remoto  --  Reemplazar con el nombre de tu servidor remoto
OPTIONS (schema 'esquema_remoto', table 'alumn_audit');  -- Reemplazar

CREATE FOREIGN TABLE public.course_audit (
    "operation" CHAR(1),
    "stamp" TIMESTAMP,
    "course_id" INTEGER,
    "id" INTEGER,
    "teacher_id" INTEGER,
    "name" VARCHAR(255),
    "lastmodified" TIMESTAMP
)
SERVER mi_servidor_remoto  --  Reemplazar
OPTIONS (schema 'esquema_remoto', table 'course_audit'); -- Reemplazar

CREATE FOREIGN TABLE public.teacher_audit (
    "operation" CHAR(1),
    "stamp" TIMESTAMP,
    "userid" VARCHAR,
    "id" INTEGER,
    "name" VARCHAR(255),
    "lastmodified" TIMESTAMP,
    "nota" TEXT,
    "hash_password" TEXT
)
SERVER mi_servidor_remoto  -- Reemplazar
OPTIONS (schema 'esquema_remoto', table 'teacher_audit'); -- Reemplazar


CREATE FOREIGN TABLE public.course_alumn_rel_audit (
    "operation" CHAR(1),
    "stamp" TIMESTAMP,
    "userid" VARCHAR,
    "id" INTEGER,
    "alumn_id" INTEGER,
    "course_id" INTEGER,
    "lastmodified" TIMESTAMP
)
SERVER mi_servidor_remoto
OPTIONS (schema 'esquema_remoto', table 'course_alumn_rel_audit');

-- Instalar extensiones necesarias
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS pgrouting;

-- Modificar tabla alumn para añadir geolocalización
ALTER TABLE alumn ADD COLUMN geom GEOMETRY(Point, 4326);
CREATE INDEX alumn_geom_idx ON alumn USING GIST(geom);

-- Modificar tabla teacher para añadir geolocalización
ALTER TABLE teacher ADD COLUMN geom GEOMETRY(Point, 4326);
CREATE INDEX teacher_geom_idx ON teacher USING GIST(geom);

-- Modificar tabla course para añadir geolocalización
ALTER TABLE course ADD COLUMN geom GEOMETRY(Point, 4326);
CREATE INDEX course_geom_idx ON course USING GIST(geom);

-- Crear nueva tabla para ubicaciones
CREATE TABLE ubicaciones (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    tipo VARCHAR(50) NOT NULL,
    direccion VARCHAR(255),
    descripcion TEXT,
    geom GEOMETRY(Point, 4326),
    lastmodified TIMESTAMP DEFAULT NOW()
);
CREATE INDEX ubicaciones_geom_idx ON ubicaciones USING GIST(geom);

-- Crear tabla para red de caminos (necesaria para pgRouting)
CREATE TABLE ways (
    id SERIAL PRIMARY KEY,
    source INTEGER,
    target INTEGER,
    cost FLOAT,
    reverse_cost FLOAT,
    name VARCHAR(255),
    geom GEOMETRY(LineString, 4326)
);
CREATE INDEX ways_geom_idx ON ways USING GIST(geom);

-- Crear topología para pgRouting
SELECT pgr_createTopology('ways', 0.0001, 'geom', 'id', 'source', 'target');

-- Insertar algunas ubicaciones de ejemplo
INSERT INTO ubicaciones (nombre, tipo, direccion, descripcion, geom) VALUES
('Biblioteca Central', 'biblioteca', 'Calle Principal 123', 'Biblioteca principal del campus', ST_SetSRID(ST_MakePoint(-3.703, 40.416), 4326)),
('Cafetería Norte', 'cafeteria', 'Av. Universidad 456', 'Cafetería con terraza', ST_SetSRID(ST_MakePoint(-3.702, 40.417), 4326)),
('Laboratorio de Informática', 'laboratorio', 'Edificio Ciencias 789', 'Laboratorio con 30 ordenadores', ST_SetSRID(ST_MakePoint(-3.704, 40.415), 4326));

-- Insertar algunos caminos de ejemplo para routing
INSERT INTO ways (name, cost, reverse_cost, geom) VALUES
('Camino A', 1.0, 1.0, ST_GeomFromText('LINESTRING(-3.703 40.416, -3.702 40.417)', 4326)),
('Camino B', 1.0, 1.0, ST_GeomFromText('LINESTRING(-3.702 40.417, -3.704 40.415)', 4326)),
('Camino C', 1.0, 1.0, ST_GeomFromText('LINESTRING(-3.703 40.416, -3.704 40.415)', 4326));

-- Actualizar la topología después de insertar caminos
SELECT pgr_createTopology('ways', 0.0001, 'geom', 'id', 'source', 'target');

-- Funciones útiles para convertir coordenadas
CREATE OR REPLACE FUNCTION update_user_location(user_id INTEGER, lat FLOAT, lon FLOAT) 
RETURNS BOOLEAN AS $$
BEGIN
    UPDATE alumn SET geom = ST_SetSRID(ST_MakePoint(lon, lat), 4326)
    WHERE id = user_id;
    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- Función para encontrar ubicaciones cercanas
CREATE OR REPLACE FUNCTION find_nearby_locations(lat FLOAT, lon FLOAT, radius FLOAT DEFAULT 1000) 
RETURNS TABLE(id INTEGER, nombre VARCHAR, tipo VARCHAR, distancia FLOAT) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        u.id, 
        u.nombre, 
        u.tipo, 
        ST_Distance(
            u.geom::geography, 
            ST_SetSRID(ST_MakePoint(lon, lat), 4326)::geography
        ) AS distancia
    FROM 
        ubicaciones u
    WHERE 
        ST_DWithin(
            u.geom::geography, 
            ST_SetSRID(ST_MakePoint(lon, lat), 4326)::geography, 
            radius
        )
    ORDER BY 
        distancia;
END;
$$ LANGUAGE plpgsql;