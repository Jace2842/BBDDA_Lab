-- Estudiantes
INSERT INTO estudiantes (nombre, fecha_nacimiento) VALUES
('Ana Torres', '2003-06-21'),
('Luis Gómez', '2002-09-13'),
('María Ruiz', '2003-01-08');

-- Asignaturas
INSERT INTO asignaturas (nombre, curso) VALUES
('Matemáticas', 1),
('Historia', 1),
('Física', 2);

-- Matriculaciones
INSERT INTO matriculaciones (estudiante_id, asignatura_id, fecha_matricula) VALUES
(1, 1, '2023-09-01'),
(1, 2, '2023-09-01'),
(2, 1, '2023-09-01'),
(2, 3, '2023-09-01'),
(3, 2, '2023-09-01');

-- Evaluaciones
INSERT INTO evaluaciones (matriculacion_id, nota, fecha_evaluacion) VALUES
(1, 8.5, '2024-01-10'),
(2, 7.2, '2024-01-12'),
(3, 6.8, '2024-01-15'),
(4, 9.0, '2024-01-11'),
(5, 7.5, '2024-01-13');
