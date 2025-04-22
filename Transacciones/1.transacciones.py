import psycopg2

# Configuración de conexión
DB_CONFIG = {
    "dbname": "mi_base_de_datos",
    "user": "mi_usuario",
    "password": "mi_contraseña",
    "host": "localhost",
    "port": "5432"
}

def transferir_fondos(origen, destino, monto):
    try:
        # Conectar con la base de datos
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False  # Desactivar autocommit para usar transacciones
        cursor = conn.cursor()

        # Verificar saldo suficiente en la cuenta origen
        cursor.execute("SELECT saldo FROM cuentas WHERE nombre = %s", (origen,))
        saldo_origen = cursor.fetchone()

        if saldo_origen is None:
            raise Exception("Cuenta de origen no encontrada")
        if saldo_origen[0] < monto:
            raise Exception("Saldo insuficiente")

        # Realizar la transferencia
        cursor.execute("UPDATE cuentas SET saldo = saldo - %s WHERE nombre = %s", (monto, origen))
        cursor.execute("UPDATE cuentas SET saldo = saldo + %s WHERE nombre = %s", (monto, destino))

        # Confirmar la transacción
        conn.commit()
        print(f"OK Transferencia de ${monto} de {origen} a {destino} completada.")

    except Exception as e:
        conn.rollback()  # Revertir cambios en caso de error
        print(f"X Error: {e}. Se ha revertido la transacción.")
    
    finally:
        cursor.close()
        conn.close()

# Prueba del programa
transferir_fondos("Alice", "Bob", 200)
