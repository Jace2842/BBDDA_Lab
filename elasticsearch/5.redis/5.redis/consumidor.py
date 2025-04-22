# consumer.py
import redis

r = redis.Redis()

print("Esperando tareas...")
while True:
    tarea = r.blpop("tareas")  # espera si la cola está vacía
    print("Ejecutando:", tarea[1].decode())
