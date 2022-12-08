`SQL` - `Structured Query Language`

## ¶‣ Advanced SQL Injection for AWAE

```
Goal is to master SQL Injection Discovery, Detection and Exploitation
```
> - Footnotes:
>   - [Advanced SQL Injection Cheatsheet](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet)
>   - Rigorous Google Dorking
>   - Reddit Dorking


<div align = center>
<br>
<img src=https://user-images.githubusercontent.com/68887544/187086211-df31719f-d22a-44ee-9e51-f34f67d42add.png width = 800px/>
<br>
<br>
</div>

## Table of Content

```
- Learning a lil' bit of SQL
- SQL Injection Methodology Overview
- MYSQL Injection Methodology
- PostgreSQL Injection Methodology
- Oracle Injection Methodology
- MSSQL Injection Methodology
```


## Learning a lil' bit of SQL

- [Learn SQL with simple, interactive exercises (sqlbolt)](https://sqlbolt.com/)
- [HackerRank SQL](https://www.hackerrank.com/domains/sql)
- Others:
> - Codewars SQL (Google it!)
> - Stratascratch SQL
> - pgexercises.com/questions/basic
> - app.sixweeksql.com
> - mystery.knightlab.com
> - schemaverse.com
> - mode.com/sql-tutorial
> - advancedsqlpuzzles.com
> - www.w3schools.com/sql/exercise.asp
> - bipp.io/sql-tutorial
> - learnsql.com
> - selectstarsql.com
> - www.sql-ex.ru
> - www.sqlservercentral.com/stairways

---

- Some important SQL Commands:

> - `SELECT` - extracts data from a database
> - `UPDATE` - updates data in a database
> - `DELETE` - deletes data from a database
> - `INSERT INTO` - inserts new data into a database
> - `CREATE DATABASE` - creates a new database
> - `ALTER DATABASE` - modifies a database
> - `CREATE TABLE` - creates a new table
> - `ALTER TABLE` - modifies a table
> - `DROP TABLE` - deletes a table
> - `CREATE INDEX` - creates an index (search key)
> - `DROP INDEX` - deletes an index

<div align = center>
<br>
<img src=https://user-images.githubusercontent.com/68887544/187085819-94fadcdf-e87b-4885-b1e3-4b77b6e64fe3.png width = 800px/>
<br>
<br>
</div>

---

## SQL Injection Methodology Overview

```
- Find Injection Point
- Understand the Website behavior
- Send queries for enumeration
- Understanding WAF & bypass it
- Dump the database
```
