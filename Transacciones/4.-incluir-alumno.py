import psycopg2

# Configuración de conexión
DB_CONFIG = {
    "dbname": "mi_base_de_datos",
    "user": "mi_usuario",
    "password": "mi_contraseña",
    "host": "localhost",
    "port": "5432"
}

def matricular_estudiante(estudiante_id, curso_id):
    try:
        # Conectar con la base de datos
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False  # Desactivar autocommit para manejar transacciones
        cursor = conn.cursor()

        # 1 Obtener datos del estudiante y curso
        cursor.execute("SELECT saldo FROM estudiantes WHERE id = %s", (estudiante_id,))
        estudiante = cursor.fetchone()
        if not estudiante:
            raise Exception("X Estudiante no encontrado.")

        cursor.execute("SELECT precio, cupo_disponible FROM cursos WHERE id = %s", (curso_id,))
        curso = cursor.fetchone()
        if not curso:
            raise Exception("x Curso no encontrado.")

        saldo_actual = estudiante[0]
        precio_curso = curso[0]
        cupo_disponible = curso[1]

        # Verificar saldo suficiente
        if saldo_actual < precio_curso:
            raise Exception("X Saldo insuficiente para matricularse.")

        # Verificar cupo disponible
        if cupo_disponible <= 0:
            raise Exception("X No hay cupos disponibles en el curso.")

        # Registrar la matrícula
        cursor.execute(
            "INSERT INTO matriculas (estudiante_id, curso_id) VALUES (%s, %s)",
            (estudiante_id, curso_id)
        )

        # Descontar saldo del estudiante
        cursor.execute(
            "UPDATE estudiantes SET saldo = saldo - %s WHERE id = %s",
            (precio_curso, estudiante_id)
        )

        # Reducir cupo del curso
        cursor.execute(
            "UPDATE cursos SET cupo_disponible = cupo_disponible - 1 WHERE id = %s",
            (curso_id,)
        )

        #  Confirmar la transacción
        conn.commit()
        print(f"OK Matrícula exitosa: Estudiante {estudiante_id} inscrito en el curso {curso_id}.")

    except Exception as e:
        # Si algo falla, revertir la transacción
        conn.rollback()
        print(f"------------x Error: {e}. Se ha revertido la transacción.")

    finally:
        cursor.close()
        conn.close()

# Prueba del programa
matricular_estudiante(1, 1)  # Intenta matricular al estudiante ID 1 en el curso ID 1
