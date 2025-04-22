# producer.py
import redis

r = redis.Redis()
r.rpush("tareas", "tarea_1")
r.rpush("tareas", "tarea_2")
print("Tareas enviadas a la cola.")
