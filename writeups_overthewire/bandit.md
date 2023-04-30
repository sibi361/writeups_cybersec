#### Writeup on https://overthewire.org/wargames/bandit/

#### Level 0 → Level 1

```
ssh bandit0@bandit.labs.overthewire.org -p 2220
cat readme # cat command prints contents of given files
```

#### Level 1 → Level 2

```
cat ./-
```

#### Level 2 → Level 3

```
cat "spaces in this filename"
```

#### Level 3 → Level 4

```
cd inhere # change directory
ls -a # list all files; with -a flag ls also lists hidden files (files starting with “.”)
cat .hidden
```

#### Level 4 → Level 5

```
cd inhere
ls -a # gives multiple files with the name pattern -file0*
file ./* # ./-file07: ASCII text; file command tells us what type of data a given file contains
cat ./-file07
```

#### Level 5 → Level 6

```
cd inhere
find . -size 1033c # size flag is used to specify size of file; 1033c = 1033 bytes; found by going through find command man page using “man find”
ls -l ./maybehere07/.file2 # returns (-rw-r-----...) which has no x means its not executable
file ./maybehere07/.file2 # returns “ASCII text, with very long lines (1000)”
cat ./maybehere07/.file2
```

#### Level 6 → Level 7

```
find / -size 33c -user bandit7 -group bandit6 # / tells the command to search the entire system as / refers to the root directory
cat /var/lib/dpkg/info/bandit7.password
```

#### Level 7 → Level 8

```
cat data.txt | grep ^millionth # ^ refers to start of line and | is the pipe operator ie output of command on left is given to the command on right as standard input
```

#### Level 8 → Level 9

```
sort data.txt | uniq -u # uniq command with -u flag shows lines whose count is 1
# sort command is needed to give sorted input as it is is required because uniq can find duplicates only if they are on adjacent lines
```

#### Level 9 → Level 10

```
cat data.txt | grep -a === # -a flag allows searching binary files as if they were human readable aka it allows finding utf8 encoding text within binary files which are usually in some encoding other than utf8
```

#### Level 10 → Level 11

```
cat data.txt | base64 -d # -d flag is used to decode base64 encoded data
```

#### Level 11 → Level 12

```
cat data.txt | tr a-zA-Z n-za-mN-ZA-M # to decode rot13 rotate every alphabet character by 13 places; tr command syntax: tr <if this character or a character in this range is found> <replace with this character or the character in this range that’s at the same position as the found character in the other given range>
#### Level 12  →  Level 13
mkdir /tmp/pras_temp_folder
cd /tmp/pras_temp_folder
cp ~/data.txt .
file data.txt # returns data.txt: ASCII text
cat data.txt # but on doing this we see that the file in fact contains hexadecimal (...1f8b 0808 3d05…)
xxd -r data.txt > out1 # -r flag used to convert hexadecimal back to binary
file out1 # says out1: gzip compressed data
mv out1 out1.gz # to decompress gzip .gz extension is mandatory
gunzip -k out1.gz # -k flag keeps original file
ls
file out1 # running file command on out1(decompressed content of initial out1.gz) gives bzip2 compressed data
bzcat out1 > out2 # decompressing the bzip out1; > operator pushes output of command on left to the filename given on the right
ls
file out2 # out2: gzip compressed data
mv out2 out2.gz # to decompress gzip .gz extension is mandatory
gunzip -k out2.gz
ls
file out2 # out2: POSIX tar archive
tar -xf out2
ls
file data5.bin # data5.bin: POSIX tar archive
tar -xf data5.bin
ls -t # sorts by time modified old to new
file data6.bin # data6.bin: bzip2 compressed data
bzcat data6.bin > data6.out
ls
file data6.out # data6.out: POSIX tar archive
tar -xf data6.out
ls -t
file data8.bin
data8.bin: gzip compressed data
mv data8.bin data8.bin.gz
gunzip -k data8.bin.gz
ls
cat data8.bin
```

#### Level 13 → Level 114

```
ls # sshkey.private private key file available
ssh -i sshkey.private bandit14@localhost -p 2220 # -i flag is used to provide private key file
```

#### Level 14 → Level 15

```
telnet localhost 30000 # pasting password here; telnet was a suggested command
```

#### Level 15 → Level 16

```
openssl s_client --connect localhost:30001 --quiet # pasting password here
```

#### Level 16 → Level 17

```
nmap localhost -p 31000-32000 # -p flag used to give range of ports to nmap
nmap -A  localhost -p 31046,31518,31691,31790,31960 # running nmap again on ports returned by previous command with the advanced flag -A (will tell which port has proper ssh server running)
openssl s_client --connect localhost:31790 –quiet # returns a private key file which is used to login to level 17
mkdir /tmp/pras5678/
cd /tmp/pras5678/
nano sshkey.pem # pasting sshkey into this file and saving
ssh -i sshkey.pem bandit17@localhost -p 2220
chmod 400 sshkey.pem # setting to “read only by owner” because of error in previous command: It is required that your private key files are NOT accessible by others
ssh -i sshkey.pem bandit17@localhost -p 2220
```

#### Level 17 → Level 18

```
diff passwords.* # find differences line by line in two given files
```

#### Level 18 → Level 19

```
scp -P 2220 bandit18@bandit.labs.overthewire.org:/home/bandit18/readme . # unable to get a bash shell but we can access the directories with scp
```

#### Level 19 → Level 20

```
./bandit20-do cat /etc/bandit_pass/bandit20 # the file which is owned by bandit20, as it has a setuid (s) permission, when a command is passed to it, it is run as that user. Therefore when used to cat the /etc/bandit_pass/bandit20/ file which is owned by bandit20, we can view its contents
```

#### Level 20 → Level 21

```
echo <password of level 20> | nc -l 7890 & # -l flag makes netcat listen to requests, “&” makes it run in background
./suconnect 7890 # as soon as a request reaches the active netcat listener it sends the level 20 password and the level 21 password is obtained
```

#### Level 21 → Level 22

```
head /etc/cron.d/* # shows first 10 lines of the file or of all the files in the given directory
cat /usr/bin/cronjob_bandit22.sh # * * * * * tells us that the script is run every minute; its contents show that the password is sent to /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

#### Level 22 → Level 23

```
head /etc/cron.d/*
cat /usr/bin/cronjob_bandit23.sh
echo I am user bandit23 | md5sum | cut -d ' ' -f 1 # performing the commands in the script as if we were user bandit23
cat /tmp/8ca319486bfbbc3663ea0fbe81326349/
```

#### Level 23 → Level 24

```
head /etc/cron.d/*
cat /usr/bin/cronjob_bandit24.sh
```

```
nc -l 7890 & # run a netcat listener in the background on port 7890
cd /var/spool/bandit24/foo/
nano getpass.sh; chmod +x getpass.sh
```

Reading the script (which executes every minute due to \* \* \* \* \*) we find that it deletes all files in the `/var/spool/bandit24/foo/` directory with the exception of files owned by `bandit23`, which are allowed to run for 90 seconds after which they are deleted. In order to read `/etc/bandit_pass/bandit24` we need a way to receive the data. For that a netcat listener can be running and then we write the following `getpass.sh` script and place it in the `/var/spool/bandit24/foo/` folder

`getpass.sh` script:

```
#!/bin/bash
curl -d @/etc/bandit_pass/bandit24 localhost:7890 # -d flag is used to send data and @ is used to read local files
```

Within a minute, the background `netcat` process will be called and it would print the contents of `/etc/bandit_pass/bandit24` to standard output, which were sent to it by `curl`

#### Level 24 → Level 25

```
telnet localhost 30002 # guessed that its telnet as neither ssh nor openssl s_client were working
for i in {0000..9999}; do echo "<level 23 password>" $i; done > possibilities.txt # locally ran to generate all possible combinations
# pasted contents of possibilities.txt into the telnet shell; although the connection started buffering, after a while the password was returned and the connection was closed when the line with the correct pin was read
```

#### End of writeup
