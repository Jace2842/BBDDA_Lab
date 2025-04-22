SELECT *
FROM crosstab(
  'SELECT sale_date, category, SUM(revenue)
   FROM sales
   JOIN products ON sales.product_id = products.product_id
   GROUP BY 1, 2
   ORDER BY 1, 2',
  'SELECT DISTINCT category FROM products'
) AS ct (sale_date DATE, "Category A" NUMERIC, "Category B" NUMERIC, ...);
