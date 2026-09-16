
import duckdb
#select from where group_by having order_by
con = duckdb.connect("test.duckdb")
con.execute("create or replace table connections as select * from data.csv")
#print(con.execute("select * from connections where packet_length>100").df())

print("port based attack")
print(con.execute("select ipsrc , count(distinct tcpdst) as counting from connections group by ipsrc having counting>5 order by count(*) desc").df())


print("syn flooding")

print(con.execute("select ipsrc,count(tcpflags)as syn_count, count(distinct tcpdst) as distinct from connections where tcpflags='S' group by ipsrc having syn_count>10 ").df())
#count(*) also true coz it counts rows and we are already filtering flags using where
