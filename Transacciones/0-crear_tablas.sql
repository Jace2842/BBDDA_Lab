CREATE TABLE cuentas (
    id SERIAL PRIMARY KEY,
    nombre TEXT NOT NULL,
    saldo NUMERIC NOT NULL
);

INSERT INTO cuentas (nombre, saldo) VALUES 
('Alice', 1000),
('Bob', 500);
