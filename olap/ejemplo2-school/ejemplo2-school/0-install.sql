CREATE TABLE estudiantes (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(100),
    fecha_nacimiento DATE
);

CREATE TABLE asignaturas (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(100),
    curso INT
);

CREATE TABLE matriculaciones (
    id SERIAL PRIMARY KEY,
    estudiante_id INT REFERENCES estudiantes(id),
    asignatura_id INT REFERENCES asignaturas(id),
    fecha_matricula DATE
);

CREATE TABLE evaluaciones (
    id SERIAL PRIMARY KEY,
    matriculacion_id INT REFERENCES matriculaciones(id),
    nota NUMERIC(4,2),
    fecha_evaluacion DATE
);
