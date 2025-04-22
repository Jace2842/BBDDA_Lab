import psycopg2
from config import load_config
from Lab1 import matricular_estudiante 

"""
tablas 

alumn :
id (SERIAL PRIMARY KEY)
first_name (VARCHAR(255) NOT NULL)
last_name (VARCHAR(255) NOT NULL)
street_address (VARCHAR(255) NOT NULL)
birthday (date)


teacher :
id (SERIAL PRIMARY KEY)
name (VARCHAR(255) NOT NULL)


course :
id (SERIAL PRIMARY KEY)
teacher_id (INTEGER)
name (VARCHAR(255) NOT NULL)


course_alumn_rel :
alumn_id (INTEGER NOT NULL)
course_id (INTEGER NOT NULL)
PRIMARY KEY (alumn_id, course_id)

Preguntas SQL a desarrollar:
1. ¿Cuáles son los alumnos con la mayor carga académica? (Los que están inscritos en
más asignaturas).
2. ¿Qué porcentaje de alumnos está inscrito en al menos una asignatura?
3. ¿Cuál es la distribución de edades de los alumnos por asignatura? (Promedio de
edad por curso).
4. ¿Qué alumnos comparten más asignaturas entre sí? (Alumnos con más asignaturas
en común).
5. ¿Cuáles son los alumnos que no están inscritos en ninguna asignatura?
6. ¿Cuál es el profesor con más alumnos?
7. ¿Cuál es el profesor que imparte más asignaturas?
8. ¿Cuál es la proporción de alumnos por profesor? (Promedio de alumnos por cada
profesor).
9. ¿Cuál es la asignatura con más alumnos por profesor?
10. ¿Hay algún profesor que no tenga asignaturas asignadas?
11. ¿Cuál es la asignatura con más alumnos inscritos?
12. ¿Cuál es la asignatura con menos alumnos inscritos?
13. ¿Cuántos cursos no tienen alumnos inscritos?
14. ¿Cuál es el promedio de alumnos por asignatura?
15. ¿Cuántos cursos son impartidos por más de un profesor? (Si en el modelo se
permitiera esto).
16. ¿Cuál es la correlación entre la edad de los alumnos y las asignaturas que toman?
17. ¿Cuál es el curso con la mayor diversidad de edades entre sus alumnos?
18. ¿Cuáles son los profesores que tienen alumnos en común? (Profesores que
enseñan a los mismos alumnos).
19. ¿Hay alguna relación entre la cantidad de asignaturas y la distribución geográfica
de los alumnos?
20. ¿Cuáles son los alumnos que tienen profesores en común en diferentes
asignaturas?

"""

def execute_query(query):
    """Ejecutar una consulta y devolver los resultados."""
    try:
        config = load_config()
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                return cur.fetchall()
    except (Exception, psycopg2.DatabaseError) as error:
        print("Error ejecutando la consulta:", error)
        return []



def EJ1():
    '1. Obtener alumnos con mayor carga académica.'
    query = """
    SELECT alumn.id, alumn.first_name, alumn.last_name, COUNT(course_alumn_rel.course_id) AS total_courses
    FROM alumn
    JOIN course_alumn_rel ON alumn.id = course_alumn_rel.alumn_id
    GROUP BY alumn.id
    ORDER BY total_courses DESC
    LIMIT 10;
    """
    return execute_query(query)

def EJ2():
    '2. Obtener porcentaje de alumnos inscritos en al menos una asignatura.'
    query = """
    SELECT (COUNT(DISTINCT alumn_id) * 100.0 / (SELECT COUNT(*) FROM alumn)) AS percentage
    FROM course_alumn_rel;
    """
    return execute_query(query)

def EJ3():
    '3. Obtener la distribución de edades por asignatura.'
    query = """
    SELECT course.id, course.name, AVG(EXTRACT(YEAR FROM AGE(alumn.birthday))) AS average_age
    FROM course
    JOIN course_alumn_rel ON course.id = course_alumn_rel.course_id
    JOIN alumn ON course_alumn_rel.alumn_id = alumn.id
    GROUP BY course.id;
    """
    return execute_query(query)

def EJ4():
    '4. Obtener los alumnos con más asignaturas en común.'
    query = """
    SELECT a1.id AS student1, a2.id AS student2, COUNT(*) AS common_courses
    FROM course_alumn_rel c1
    JOIN course_alumn_rel c2 ON c1.course_id = c2.course_id AND c1.alumn_id < c2.alumn_id
    JOIN alumn a1 ON c1.alumn_id = a1.id
    JOIN alumn a2 ON c2.alumn_id = a2.id
    GROUP BY a1.id, a2.id
    ORDER BY common_courses DESC
    LIMIT 10;
    """
    return execute_query(query)

def EJ5():
    '5. Obtener alumnos que no están inscritos en ninguna asignatura.'
    query = """
    SELECT alumn.id, alumn.first_name, alumn.last_name
    FROM alumn
    LEFT JOIN course_alumn_rel ON alumn.id = course_alumn_rel.alumn_id
    WHERE course_alumn_rel.alumn_id IS NULL;
    """
    return execute_query(query)


def EJ6():
    '6. ¿Cuál es el profesor con más alumnos?.'
    query = """
    SELECT teacher.id, teacher.name AS teachers
    FROM teacher
    JOIN course ON teacher.id = course.teacher_id
    JOIN course_alumn_rel ON course.id = course_alumn_rel.course_id
    GROUP BY teacher.id
    ORDER BY teachers DESC
    LIMIT 1;
    """
    return execute_query(query)

def EJ7():
    """7. Obtener el profesor que imparte más asignaturas."""
    query = """
    SELECT teacher.id, teacher.name, COUNT(course.id) AS total_courses
    FROM teacher
    JOIN course ON teacher.id = course.teacher_id
    GROUP BY teacher.id
    ORDER BY total_courses DESC
    LIMIT 1;
    """
    return execute_query(query)

def EJ8():
    """8. Obtener la proporción de alumnos por profesor."""
    query = """
    SELECT AVG(student_count) AS average_students_per_teacher
    FROM (
        SELECT teacher.id, COUNT(DISTINCT course_alumn_rel.alumn_id) AS student_count
        FROM teacher
        JOIN course ON teacher.id = course.teacher_id
        JOIN course_alumn_rel ON course.id = course_alumn_rel.course_id
        GROUP BY teacher.id
    ) AS student_counts;
    """
    return execute_query(query)
def EJ9():
    """¿Cuál es la asignatura con más alumnos por profesor?"""
    query = """
    SELECT course.id, course.name,COUNT(course_alumn_rel.alumn_id) / COUNT(DISTINCT course.teacher_id) AS courses
    FROM course
    JOIN course_alumn_rel ON course.id = course_alumn_rel.course_id
    GROUP BY course.id
    ORDER BY courses DESC
    LIMIT 10;
    """
    return execute_query(query)

def EJ10():
    """10. Obtener profesores que no tienen asignaturas asignadas."""
    query = """
    SELECT teacher.id, teacher.name
    FROM teacher
    LEFT JOIN course ON teacher.id = course.teacher_id
    WHERE course.id IS NULL;
    """
    return execute_query(query)

def EJ11():
    """11. Obtener la asignatura con más alumnos inscritos."""
    query = """
    SELECT course.id, course.name, COUNT(course_alumn_rel.alumn_id) AS total_students
    FROM course
    JOIN course_alumn_rel ON course.id = course_alumn_rel.course_id
    GROUP BY course.id
    ORDER BY total_students DESC
    LIMIT 1;
    """
    return execute_query(query)

def EJ12():
    """12. Obtener la asignatura con menos alumnos inscritos."""
    query = """
    SELECT course.id, course.name, COUNT(course_alumn_rel.alumn_id) AS total_students
    FROM course
    LEFT JOIN course_alumn_rel ON course.id = course_alumn_rel.course_id
    GROUP BY course.id
    ORDER BY total_students ASC
    LIMIT 1;
    """
    return execute_query(query)

def EJ13():
    """13. Obtener el número de cursos sin alumnos inscritos."""
    query = """
    SELECT COUNT(*)
    FROM course
    LEFT JOIN course_alumn_rel ON course.id = course_alumn_rel.course_id
    WHERE course_alumn_rel.course_id IS NULL;
    """
    return execute_query(query)

def EJ14():
    """14. Obtener el promedio de alumnos por asignatura."""
    query = """
    SELECT AVG(student_count) AS average_students_per_course
    FROM (
        SELECT course.id, COUNT(course_alumn_rel.alumn_id) AS student_count
        FROM course
        LEFT JOIN course_alumn_rel ON course.id = course_alumn_rel.course_id
        GROUP BY course.id
    ) AS student_counts;
    """
    return execute_query(query)

def EJ15():
    """15. Obtener cuántos cursos son impartidos por más de un profesor."""
    query = """
    SELECT COUNT(*)
    FROM (
        SELECT course.id
        FROM course
        GROUP BY course.id
        HAVING COUNT(DISTINCT course.teacher_id) > 1
    ) AS multiple_teachers_courses;
    """
    return execute_query(query)

def EJ16():
    """16. Obtener la correlación entre la edad de los alumnos y las asignaturas que toman."""
    query = """
    SELECT CORR(EXTRACT(YEAR FROM AGE(a.birthday)), course_count) 
    FROM (
        SELECT alumn_id, COUNT(course_id) AS course_count
        FROM course_alumn_rel 
        GROUP BY alumn_id
    ) AS alumn_courses
    JOIN alumn a ON a.id = alumn_courses.alumn_id;
    """
    return execute_query(query)

def EJ17():
    """17. Obtener el curso con la mayor diversidad de edades entre sus alumnos."""
    query = """
    SELECT c.id, c.name, MAX(EXTRACT(YEAR FROM AGE(a.birthday))) - MIN(EXTRACT(YEAR FROM AGE(a.birthday))) AS age_range
    FROM course c
    JOIN course_alumn_rel car ON c.id = car.course_id
    JOIN alumn a ON car.alumn_id = a.id
    GROUP BY c.id, c.name
    ORDER BY age_range DESC
    LIMIT 1;
    """
    return execute_query(query)

def EJ18():
    """18. Obtener los profesores que tienen alumnos en común."""
    query = """
    SELECT DISTINCT t1.id AS teacher1_id, t1.name AS teacher1_name, 
                    t2.id AS teacher2_id, t2.name AS teacher2_name
    FROM course c1
    JOIN course_alumn_rel car1 ON c1.id = car1.course_id
    JOIN course c2 ON c1.teacher_id <> c2.teacher_id
    JOIN course_alumn_rel car2 ON c2.id = car2.course_id
    JOIN teacher t1 ON c1.teacher_id = t1.id
    JOIN teacher t2 ON c2.teacher_id = t2.id
    WHERE car1.alumn_id = car2.alumn_id;
    """
    return execute_query(query)

def EJ19():
    """19. Analizar la relación entre la cantidad de asignaturas y la distribución geográfica de los alumnos."""
    query = """
    SELECT a.street_address, COUNT(car.course_id) AS total_courses
    FROM alumn a
    JOIN course_alumn_rel car ON a.id = car.alumn_id
    GROUP BY a.street_address
    ORDER BY total_courses DESC;
    """
    return execute_query(query)

def EJ20():
    """20. Obtener los alumnos que tienen profesores en común en diferentes asignaturas."""
    query = """
    SELECT DISTINCT a.id, a.first_name, a.last_name
    FROM course_alumn_rel car1
    JOIN course_alumn_rel car2 ON car1.alumn_id = car2.alumn_id AND car1.course_id <> car2.course_id
    JOIN course c1 ON car1.course_id = c1.id
    JOIN course c2 ON car2.course_id = c2.id
    WHERE c1.teacher_id = c2.teacher_id;
    """
    return execute_query(query)





def alumnos():
    query="""
     select count(*) 
     from  course_alumn_rel
     
     """ 
    return execute_query(query)

def alter():
    query="""
     alter 
     from  course_alumn_rel
     
     """ 
    return execute_query(query)
print("resultado:",matricular_estudiante(1000007,15000))

