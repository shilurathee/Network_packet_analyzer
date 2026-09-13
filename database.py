import duckdb

print("duck db version : ",duckdb.__version__)
result = duckdb.sql("SELECT 10 + 20")

print(result.fetchall())