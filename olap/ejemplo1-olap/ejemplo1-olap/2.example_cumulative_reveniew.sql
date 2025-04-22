SELECT
  sale_date,
  SUM(revenue) OVER (ORDER BY sale_date) AS cumulative_revenue
FROM sales
ORDER BY sale_date;