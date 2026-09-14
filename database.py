
import duckdb,pandas as pd

def resolve(dataframe):
    con =duckdb.connect("network_data.duckdb")
    
    df=dataframe
    con.execute(create table packet_table as select * from df)
    
