
import duckdb
#select from where group_by having order_by
con = duckdb.connect("test.duckdb")
con.execute("create or replace table connections as select * from data.csv")
#print(con.execute("select * from connections where packet_length>100").df())

#port based attack
print(con.execute("select ipsrc , count(distinct tcpdst) as counting from connections group by ipsrc having counting>1 order by count(*) desc").df())
