CREATE TABLE sales (
  sale_id serial PRIMARY KEY,
  sale_date DATE,
  product_id INT,
  quantity INT,
  revenue NUMERIC(10, 2)
);

CREATE TABLE products (
  product_id serial PRIMARY KEY,
  product_name VARCHAR(100),
  category VARCHAR(50)
);