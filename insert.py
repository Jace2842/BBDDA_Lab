import psycopg2
from config import load_config
from faker import Faker
import random
NUM_TEACHERS = 10000
NUM_COURSES = 150000
NUM_ALUMNS = 1000000
COURSE_TABLE = 'course'
ALUMN_TABLE = 'alumn'
TEACHER_TABLE = 'teacher'
COURSE_ALUMN_REL = 'course_alumn_rel'
NUM_ALUMN_PER_COURSE = 50

import logging

# Obtener un logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
import inspect

def insert_many(table, columns, values):
    """ Insert multiple vendors into the vendors table  """
    funcion_actual = inspect.currentframe().f_code.co_name
    logger.info("{0} en tabla {1}, #{2}.".format(funcion_actual, table, len(values)))
    param = []
    for i in range(columns.count(',') + 1):
        param.append("%s")
    param = ', '.join(param)
    sql = "INSERT INTO " + table + "( " + columns + ") VALUES(" + param + ") RETURNING *;"
    config = load_config()
    try:
        with  psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                # execute the INSERT statement
                cur.executemany(sql, values)
            # commit the changes to the database
            conn.commit()
        logger.info("{0} en tabla {1}, #{2}. Generados correctamente. ".format(funcion_actual, table, len(values)))
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)


def import_data_alumn(fake, num):

    data = []
    funcion_actual = inspect.currentframe().f_code.co_name
    logger.info("{0} en tabla {1}, #{2}.".format(funcion_actual, ALUMN_TABLE, num))
    for i in range(0, num):
        first_name = fake.first_name()
        last_name = fake.last_name()
        street_address = fake.street_address()
        birthday = fake.date_time_between(start_date='-50y', end_date='now')
        data.append([first_name, last_name, street_address, birthday])
    logger.info("{0} Datos generados.".format(funcion_actual))
    return insert_many(ALUMN_TABLE, 'first_name, last_name, street_address, birthday', data)


def import_data_teacher(fake, num):
    data = []
    funcion_actual = inspect.currentframe().f_code.co_name
    logger.info("{0} en tabla {1}, #{2}.".format(funcion_actual, ALUMN_TABLE, num))
    for i in range(0, num):
        data.append([fake.name()])
    logger.info("{0} Datos generados.".format(funcion_actual))
    return insert_many(TEACHER_TABLE, 'name', data)


def import_data_course(fake, num, teacher_ids):
    data = []
    funcion_actual = inspect.currentframe().f_code.co_name
    logger.info("{0} en tabla {1}, #{2}.".format(funcion_actual, ALUMN_TABLE, num))
    for i in range(0, num):
        data.append((fake.name(), teacher_ids[i % NUM_TEACHERS]))
    logger.info("{0} Datos generados.".format(funcion_actual))
    return insert_many(COURSE_TABLE, 'name,teacher_id', data)


def get_elements(table):
    """ Retrieve data from the vendors table """
    config = load_config()
    funcion_actual = inspect.currentframe().f_code.co_name
    logger.info("{0} en tabla {1}.".format(funcion_actual, table))
    res = []
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT id
                                FROM """ + table + """
                                ORDER BY RANDOM();
                                """)
                res = [x[0] for x in cur.fetchall()]
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    logger.info("{0} en tabla {1}. {2}.".format(funcion_actual, table, len(res)))
    return res

def truncate_table(table):
    """ Retrieve data from the vendors table """
    config = load_config()
    funcion_actual = inspect.currentframe().f_code.co_name
    logger.info("{0} en tabla {1}.".format(funcion_actual, table))

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                cur.execute("""TRUNCATE """ + table + """;""")
            conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)


def import_data_alumn_course(course_ids, alumn_ids):
    data = []
    funcion_actual = inspect.currentframe().f_code.co_name
    logger.info("{0} en tabla {1}, #{2}.".format(funcion_actual, COURSE_ALUMN_REL, len(course_ids) * NUM_ALUMN_PER_COURSE))
    for course_id in course_ids:
        random_alumn_ids = random.sample(alumn_ids, NUM_ALUMN_PER_COURSE)
        for alumn_id in random_alumn_ids:
            data.append([course_id, alumn_id])
    logger.info("{0} Datos generados. #{1}".format(funcion_actual, len(data)))
    truncate_table(COURSE_ALUMN_REL)
    return insert_many(COURSE_ALUMN_REL, 'course_id,alumn_id', data)


if __name__ == '__main__':
    fake = Faker()
    # Generar NUM_ALUMNS de alumnos
    import_data_alumn(fake, NUM_ALUMNS)
    # Generar NUM_TEACHERS profesores
    import_data_teacher(fake, NUM_TEACHERS)
    # Generar NUM_COURSES cursos
    # Asociar todos los cursos a profesores
    teacher_ids = get_elements(TEACHER_TABLE)
    course_ids = import_data_course(fake, NUM_COURSES, teacher_ids)
    alumn_ids = get_elements(ALUMN_TABLE)
    course_ids = get_elements(COURSE_TABLE)
    # Asociar NUM_ALUMN_PER_COURSE alumnos a cada curso
    import_data_alumn_course (course_ids, alumn_ids)