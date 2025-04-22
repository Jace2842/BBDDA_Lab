CREATE TABLE estudiantes (
    id SERIAL PRIMARY KEY,
    nombre TEXT NOT NULL,
    saldo NUMERIC NOT NULL
);

CREATE TABLE cursos (
    id SERIAL PRIMARY KEY,
    nombre TEXT NOT NULL,
    precio NUMERIC NOT NULL,
    cupo_disponible INT NOT NULL
);

CREATE TABLE matriculas (
    id SERIAL PRIMARY KEY,
    estudiante_id INT REFERENCES estudiantes(id),
    curso_id INT REFERENCES cursos(id),
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insertamos datos de prueba
INSERT INTO estudiantes (nombre, saldo) VALUES ('Juan Pérez', 500);
INSERT INTO cursos (nombre, precio, cupo_disponible) VALUES ('Python Avanzado', 300, 5);
