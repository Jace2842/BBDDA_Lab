
CREATE TABLE services (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    type VARCHAR(50),
    geom GEOMETRY(Point, 4326)
);

CREATE TABLE usuarios (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100),
    geom GEOMETRY(Point, 4326)
);

CREATE TABLE localizaciones (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    geom GEOMETRY(Point, 4326)
);

INSERT INTO services (name, type, geom) VALUES
('Hospital Central', 'hospital', ST_GeomFromText('POINT(-3.70379 40.41678)', 4326)),
('Escuela Primaria', 'school', ST_GeomFromText('POINT(-3.70300 40.41500)', 4326)),
('Estación de Bomberos', 'fire_station', ST_GeomFromText('POINT(-3.70200 40.41400)', 4326));

INSERT INTO usuarios (username, geom) VALUES
('usuario1', ST_GeomFromText('POINT(-3.70450 40.41750)', 4326));

INSERT INTO localizaciones (name, geom) VALUES
('Localización X', ST_GeomFromText('POINT(-3.70100 40.41300)', 4326));


CREATE INDEX services_geom_idx ON services USING GIST (geom);
CREATE INDEX usuarios_geom_idx ON usuarios USING GIST (geom);
CREATE INDEX localizaciones_geom_idx ON localizaciones USING GIST (geom);

