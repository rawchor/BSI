# Funkcje hashujące
## Zadanie 1 (Funkcja skrótu MD5)
[Cryptography - MD5 Hash function - 1.1](https://youtu.be/qHH7pHUYEEY)

```shell
nc 10.0.45.41 1337
nc -v 10.0.45.41 1337
md5sum
	TEST
md5sum
v3AvrLucjwHp8VxfuwF7
echo "v3AvrLucjwHp8VxfuwF7"
echo -n "v3AvrLucjwHp8VxfuwF7"
echo -n "v3AvrLucjwHp8VxfuwF7" | md5sum
```

## Zadanie 2 (Funkcja skrótu SHA1)
[Cryptography 0 SHA1 hash function - 1.2](https://youtu.be/GcUuKxWN9Wk)

```shell
nc 10.0.103.30 1337
echo -n "vDfOMDspCiAUwFv59PYa" (-n removes space at the end of string before onversion)
echo -n "vDfOMDspCiAUwFv59PYa" | sha1sum
(remember to enter the answer to receive hex)
```

## Zadanie 3 (Funkcja skrótu SHA3)
[Cryptography - Hash Function SHA3 - 1.3](https://youtu.be/0dfcmc4xQJw)

```shell
python3
import hashlib
h = hashlib.sha3
h = hashlib.sha3_512()
h.update("daeWceEObsy1kPww61C2".encode("utf-8"))
h.update("ThGlOZhlSSdv3eYPybR9".encode("utf-8"))
h.digest()
h.hexdigest()
(exit - cntr D)
```

## Zadanie 4 (Łamanie skrótu MD5 metodą słownikową)
[Cryptography - breaking the MD5 hash using the dictionary method - 1.4](https://youtu.be/adagCEdB5kI)

```shell
nc 10.0.92.116 1337
echo "20fe26686fe82042f435a57aa0cb48da" > pass.txt
cat pass.txt
john --wordlist=rockyou.txt pass.txt
john --wordlist=rockyou.txt --format=raw-md5 pass.txt
```

## Zadanie 5 (Identyfikacja funkcji skrótu)
[Cryptography - Identification of hash function - 1.5](https://youtu.be/txkcG7XBOlM)

```shell
nc 10.0.121.191 1337
python3

import hashlib
hashlib.algorithms_available
s = "mQF5YZLWc0G6jfUTgILB".encode("utf-8")
hh = "013871292a755a27fe73d3b0c07363346d3beaa1"
for alg in hashlib.algorithms_available:
    try:
			h = hashlib.new(alg)
            h.update(s)
            if h.hexdigigest() == hh:
		        print("Alg: ", alg)
	except:
			print("Exception: ", alg)
```

## Zadanie 6 (Kod uwierzytelniający HMAC)
[Cryptography- HMAC authentication code - 1.6](https://youtu.be/syv4bvI73Bo)

```shell
openssl list --digest-commands
echo -n "widomosc" | openssl dgst -sha512 -hmac "klucz"
```

## Zadanie 7 (Kolizja MD5)
[Cryptography - collision MD5 - 1.7](https://youtu.be/sRWcs0Z-Qzg)

```shell
nc 10.0.17.207 1337 < answer.txt
```

## Zadanie 8 (Test sprawdzający)

1.  Algorytm MD5 generuje skrót o długości:
	*   128 bitów +
	*   60 bitów
	*   256 bitów
	*   32 bajtów
2. Algorytm SHA2-256 generuje skrót o długości:
	-   521 bitów
	-   32 bajtów +
	-   256 bajtów
	-   2^256 bitów 
3. W przypadku jednokierunkowych funkcji skrótu kolizja oznacza, że:
	-   dla określonego algorytmu dwa różne ciągi danych wejściowych generują tę samą wartość skrótu +
	-   algorytm nie jest w stanie wyliczyć wartości skrótu dla określonych danych wejściowych
	-   dwa różne algorytmy generują takie same wartości skrótu
	-   algorytm generuje błędne dane
4. Wykorzystanie funkcji skrótu pozwala na zachowanie:
	-   dostępności danych
	-   integralności wiadomości +
	-   policzalności danych i wiadomości
	-   poufności wiadomości
5. Ciąg znaków "aasb763jjab" został zapisany do pliku "file.txt" za pomocą polecenia: echo "aasb763jjab" > file.txt. Aby wygenerować skrót sha-256 dla ciągu "aasb763jjab" należy wykonać polecenie:
	-   echo -n "aasb763jjab" | sha256sum +
	-   cat file.txt | sha256sum
	-   sha256sum file.txt
	-   sha256sum < file.txt
6. W bibliotece openssl do generowania skrótów wiadomości wykorzystuje się komendę:
	-   openssl enc
	-   openssl message digest
	-   openssl sha
	-   openssl dgst +
7. Aby wygenerować skrót SHA2-256 dla ciągu "i8d6s9v4x6s1" należy wykonać polecenie:
	-   echo i8d6s9v4x6s1 | shasum -a 256
	-   shasum -a 256 < "i8d6s9v4x6s1"
	-   echo -n "i8d6s9v4x6s1" > shasum -a 256
	-   echo -n i8d6s9v4x6s1 | shasum -a 256 +
8. Kod HMAC oznacza:
	-   kod MAC wykorzystujący funkcje haszujące +
	-   kod MAC zabezpieczony dodatkowym hasłem
	-   Hashed Message Authorization Code
	-   funkcję haszującą sieciowe adresy MAC
9. Wśród wymienionych poniżej nazw algorytmów jednokierunkową funkcją skrótu nie jest:
	-   SHA
	-   AES +
	-   MD5
	-   Whirlpool
10. W przypadku jednokierunkowych funkcji skrótu kolizja oznacza, że:
	-   algorytm generuje błędne dane
	-   algorytm nie jest w stanie wyliczyć wartości skrótu dla określonych danych wejściowych
	-   dwa różne algorytmy generują takie same wartości skrótu
	-   dla określonego algorytmu dwa różne ciągi danych wejściowych generują tę samą wartość skrótu +

# Szyfrowanie symetryczne
## Zadanie 1 (Odszyfrowanie danych szyfrem AES)
[Cryptography - Decrypting data with the AES cipher - 2.1](https://youtu.be/OEswuYvywdc)

```shell
nc 10.0.34.250 1337
openssl enc -aes-256-ecb -d -a -in data.enc -K e1fb0fcdfcc1419998d98c18b8468c0a
data.enc - contains syphered letter
options below allow to enter keys with different ways
-k password
-kfile filename
-K e1fb0fcdfcc1419998d98c18b8468c0a
```

## Zadanie 2 (Odszyfrowanie pliku szyfrem AES)
[Cryptography - Decrypting a file with an AES cipher - 2.2](https://youtu.be/VBcAhNLoP9c)

```shell
-d - dysyphering
-in - entry data
-kfile - desyphering key file

openssl enc -aes-256-cbc -d -in cs.out -kfile pwd.pass -pbkdf2

```

## Zadanie 3 (Szyfrowanie danych algorytmem 3DES)
[Cryptography - Decrypting a file with an AES cipher - 2.2](https://youtu.be/EgFyOJsyk8w)

```shell
gedit data.enc
openssl enc -ciphers
openssl enc -d -a -in data.enc -k c70e5e75-252b-4491-9a44-a4838275ee1f -pbkdf2 -des-ede3-ecb
```

## Zadanie 4 (Szyfrowanie z wykorzystaniem algorytmu PBKDF1)
[Cryptography - Encryption using the PBKDF1 algorithm - 2.4](https://youtu.be/xJq2fraUZDQ)

```shell
gedit data.enc - creating file with syphered message
openssl enc -d -aes-256-ecb -k 20f4c9ef-6296-4d03-8878-f8445f0b1c9f -in data.enc -a -iter 14072
```

## Zadanie 5 (Algorytm PBKDF2 z niestandardową liczbą iteracji)
[Cryptography- PBKDF2 algorithm with non-standard number of iterations - 2.5](https://youtu.be/ZyQQRmgsZ5U)

```shell
gedit data.enc
openssl enc -d -a -aes-256-cbc -in data.enc -k 7b5ccb18-5f68-4991-a3bc-e7295a7a6893 -pbkdf2 -iter 3625505
```

## Zadanie 6 (Identyfikacja algorytmu szyfrującego)
[Cryptography - Identifying the encryption algorithm - 2.6](https://youtu.be/q_EbNioPnn4)

```shell
gedit data.enc
gedit pwd.pass
openssl enc -ciphers (find ciphers from task)
ciphers.txt (create file with required cipher extensions)
(make bash file script.sh)
run
bash script.sh < ciphers.txt
```

## Zadanie 7 (Szyfrowany plik Zip)
[Cryptography - An encrypted Zip file - 2.7](https://youtu.be/SOALDU1Kgnw)

```shell
#fcrackzip
cd Downloads
ll
fcrackzipinfo 64b980cf-309d-41e0-a230-b526357f577b.zip
fcrackzip -h
fcrackzip -D -p ../rockyou.txt 64b980cf-309d-41e0-a230-b526357f577b.zip
fcrackzip -u -D -p ../rockyou.txt 64b980cf-309d-41e0-a230-b526357f577b.zip
unzip 64b980cf-309d-41e0-a230-b526357f577b.zip 
cat secret.txt

#zip2john
zip2john 64b980cf-309d-41e0-a230-b526357f577b.zip > john.pass
zip2john -h
john --wordlist=../rockyou.txt john.pass
cat secret.txt
```

## Zadanie 8 (Test sprawdzający)

1. Skrót AES oznacza:
	-   Authorized Enhanced Security
	-   Advanced Encryption System
	-   Automatic Encryption System
	-   Advanced Encryption Standard +
2. Algorytm AES w trybie CBC do zaszyfrowania danych wymaga podania:
	-   hasła i klucza szyfrującego
	-   tylko klucza szyfrującego
	-   klucza szyfrującego oraz wektora inicjującego +
	-   hasła i wektora kończącego
3.  Wskaż, który z elementów nie decyduje o sile systemu kryptograficznego:
	-   algorytm
	-   długość szyfrogramu +
	-   bezpieczeństwo klucza
	-   wektory inicjujące
4.  Atak typu "brute-force" na kryptosystem polega na:
	-   próbie siłowego zgadnięcia klucza szyfrującego na podstawie analizy szyfrogramu
	-   deszyfrowaniu szyfrogramu za pomocą losowo generowanych kluczy
	-   próbie odszyfrowania szyfrogramu poprzez przegląd całej przestrzeni kluczy +
	-   wyodrębnieniu klucza szyfrującego z wykorzystaniem tekstu jawnego i szyfrogramu
5. Dla klucza szyfrującego o rozmiarze 256 bitów przestrzeń kluczy zawiera:
	-   nieskończenie wiele elementów
	-   2^256 elementów +
	-   256^2 elementów
	-   8 * 256 elementów
6. Algorytm 3DES to:
	-   udoskonalona wersja algorytmu AES
	-   odmiana algorytmu DES, w której szyfrowanie z wykorzystaniem DES wykonuje się trzykrotnie +
	-   inna nazwa algorytmu „des-ede-cbc”
	-   trzecia, udoskonalona wersja algorytmu DES
7. Poniżej przedstawiono fragment podręcznika systemowego dla polecenia "openssl". Szyfrowanie pliku data.txt algorytmem AES w trybie wiązania zaszyfrowanych bloków, z blokami o rozmiarze 256 bitów z hasłem "as34Dw9P2lsH" przedstawia polecenie:
	-   openssl enc -aes-256-cbc -in data.txt -out data.enc -K as34Dw9P2lsH
	-   openssl enc -e -aes-256-ebc -in data.txt -out data.enc -k as34Dw9P2lsH
	-   openssl enc -e -aes-256-cbc -in data.txt -out data.enc -k as34Dw9P2lsH +
	-   openssl enc -d -aes-256-cbc -in data.txt -out data.enc -K as34Dw9P2lsH
8. W kryptografii symetrycznej do deszyfrowania wiadomości odbiorca używa:
	-   hasła generowanego na podstawie tajnego klucza
	-   własnego klucza prywatnego
	-   klucza publicznego przesłanego przez nadawcę
	-   tego samego klucza, którym nadawca zaszyfrował wiadomość +
9. Sparametryzowany koszt obliczeniowy (work factor) w funkcjach PBKDF ma na celu:
	-   zachowanie kompatybilności z innymi funkcjami skrótu
	-   umożliwienie generowania kluczy o żądanej długości
	-   znaczące utrudnienie ataków typu "brute-force" +
	-   poprawę wydajności algorytmu
10. Różnica w pracy algorytmu szyfrującego w trybie ECB i CBC polega na tym, że:
	-   w trybie CBC każdy nowy szyfrogram bloku podpisywany jest kluczem wygenerowanym z poprzedniego bloku
	-   w trybie CBC inaczej niż w trybie ECB, każdy nowy blok danych sumowany jest modulo 2 z szyfrogramem poprzedzającego go bloku +
	-   w przeciwieństwie do trybu CBC, w trybie ECB tekst szyfrowany dzielony jest na bloki jednakowej długości
	-   w trybie ECB wykorzystywany jest klucz symetryczny, a w trybie CBC niesymetryczny
# Szyfrowanie asymetryczne
## Zadanie 1 (Generowanie kluczy RSA)
[Cryptography - Asymmetric encryption - Generating RSA keys - 3.1](https://youtu.be/18q1WOcyzWM)

```shell
openssl genrsa -out priv.pem 4096
openssl rsa -in priv.pem -text
openssl rsa -in priv.pem -pubout -out pub.pem
cat pub.pem
openssl rsa -in pub.pem -pubin -text
```

## Zadanie 2 (Generowanie kluczy na krzywych eliptycznych)
[Cryptography - asymmetric encryption - Generating keys on elliptic curves - 3.2](https://youtu.be/JpFwTpIubBo)

```shell
openssl ecparam -list_curves
openssl ecparam -name prime256v1 -genkey -out priv.pem
cat priv.pem
openssl ec -in priv.pem -out pub.pem -pubout
cat pub.pem
cat pub.pem > keys.pem
echo "" >> keys.pem
cat priv.pem >> keys.pem
cat keys.pem

```

## Zadanie 3 (Szyfrowanie kluczem publicznym)
[Cryptography - asymmetric encryption - Public key encryption - 3.3](https://youtu.be/bR74jBpT2G0)

```shell
gedit pub.pem
gedit data.txt
openssl pkeyutl -encrypt -in data.txt -inkey pub.pem -pubin -out data.enc -pkeyopt rsa_padding_mode:oaep
cat data.enc
base64 -w0 data.enc (-w0 bez przejsc nowych linii)
```

## Zadanie 4 (Certyfikat z zadanym polem Nazwa pospolita)
[Cryptography - asymmetric encryption - Certificate with given field Common name - 3.4](https://youtu.be/TaLfj2O4VAE)

```shell
mkdir ca
cd ca
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt
openssl x509 -in ca.crt -text
cat ca.crt
```

## Zadanie 5 (Certyfikat na podstawie zapytania)
[Cryptography - Asymmetric encryption - Certificate based on request - 3.5](https://youtu.be/CCimhx4Qe8o)

```shell
cd ca
gedit client.crs
openssl x509 -req -CAkey ca.key -CA ca.crt -in client.crs -CAcreateserial -out client.crt
cat client.crt
```

## Zadanie 6 (Generowanie klucza PGP)
[Cryptography - asymmetric encryption - PGP key generation - 3.6](https://youtu.be/77PLPCd250g)

```shell
gpg --gen-key
pass-Salty
gpg --list-key
gpg --export --armor Cassian Werner
armor - uzyskanie w base64
```

## Zadanie 7 (Szyfrowanie za pomocą klucza PGP)
[Cryptography - asymmetric encryption - Encryption using a PGP key - 3.7](https://youtu.be/7pyJb6hy1eo)

```shell
gedit pub.pem
gedit data.txt
gpg --show-key pub.pem
gpg --import pub.pem
gpg --encrypt --armor --recipient cyberskiller data.txt
cat data.txt.gpg
echo -n GpYoyWd8C8mwoLz1 | gpg --encrypt --armor --recipient cyberskiller
cat data.txt.asc
```

## Zadanie 8 (Odszyfrowanie za pomocą klucza PGP)
[Cryptography - asymmetric encryption - Decryption using a PGP key - 3.8](https://youtu.be/0oxzn0b75KY)

```shell
gpg --gen-key
gpg --export test
gpg --export --armor test
gedit data.enc
gpg --decrypt data.enc
```

## Zadanie 9 (Test sprawdzający)

1. Odbiorca B, w celu weryfikacji podpisanej przez nadawcę A wiadomości:
	-   wykorzysta klucz publiczny A +
	-   wykorzysta klucz publiczny B
	-   wykorzysta klucz prywatny A
	-   wykorzysta klucz prywatny B
2. W kryptosystemie RSA:
	-   odbierane wiadomości deszyfruje się kluczami prywatnymi odbiorcy +
	-   odbierane wiadomości deszyfruje się kluczami publicznymi odbiorcy
	-   odbierane wiadomości deszyfruje się kluczami prywatnymi nadawcy
	-   odbierane wiadomości deszyfruje się kluczami publicznymi nadawcy
3. Aby zaszyfrować plik data.txt o rozmiarze 4 kB wykorzystując klucz publiczny o rozmiarze 4 kb (zapisany w pliku pub.pem) należy:
	-   wygenerować losowy klucz, zaszyfrować podany plik za pomocą algorytmu symetrycznego z wykorzystaniem wygenerowanego klucza, zaszyfrować kluczem publicznym klucz symetryczny, ewentualnie przesłać odbiorcy zaszyfrowany plik wraz z zaszyfrowanym kluczem +
	-   wykonać polecenie: openssl rsautl -encrypt -inkey pub.pem -pubin -in data.txt -out data.enc
	-   wykonać polecenie: openssl rsautl -encrypt -inkey priv.pem -in data.txt -out data.enc
	-   zaimportować klucz do systemu PGP i wykonać polecenie: gpg --encrypt --key pub.pem -in data.txt
4. System GnuPG oparty jest na:
	-   rozproszonym systemie BlockChain 
	-   systemie certyfikacji scentralizowanej 
	-   modelu zaufania typu "Web of Trust" +
	-   ścisłej (nie rozproszonej) infrastrukturze PKI
5. Celem stosowania GnuPG nie jest:
	-   zachowanie rozliczalności +
	-   weryfikacja nadawcy
	-   zachowanie poufności
	-   weryfikacja integralności
6.  W kryptografii asymetrycznej:
	-   wysyłane wiadomości szyfruje się kluczami publicznymi nadawcy 
	-   wysyłane wiadomości szyfruje się kluczami prywatnymi nadawcy
	-   wysyłane wiadomości szyfruje się kluczami publicznymi odbiorcy +
	-   wysyłane wiadomości szyfruje się kluczami prywatnymi odbiorcy
7.  Podpis złożony na wiadomości gwarantuje przede wszystkim jej:
	-   dostępność
	-   integralność +
	-   prywatność 
	-   poufność 
8. Poniżej przedstawiono:
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn1HMolkYW7gJOZYBXTiw
    8xDNX4zaMxTrYW7w6/i3pHbpPGPCo+bclJvPoVZohG+QnyNJV25ILW6oJ9rqv4qq
    xesNQTTepKSguKwMAqPOlnSYwbFBJoNNuYIThNz6qaAOgIfTBFKohRbR2rECFoW7
    inkO44rok+fAmEjQvykFgO/3l5fs3D1Cqq6fN+Qk6TGHmk/hVpX4s9zPPcpm9b3H
    gvngBl3toxHPIkrHV+7xlzEAcYeZoiXofGIkWgMjGg+sOh/tPwgEviM3hFH5P0+V
    oi/Txsvv1jQvkMAVZTUyuMg4gFyv777t0BFRbWB8M1er1Qr38D+atV5bZjtIcBzE
    lwIDAQAB
    -----END PUBLIC KEY-----
	-   klucz publiczny w formacie binarnym
	-   klucz prywatny w formacie base64
	-   klucz publiczny zapisany z wykorzystaniem kodowania base64 +
	-   klucz publiczny w postaci heksadecymalnej
9. Bezpieczeństwo kryptosystemu RSA opera się na:
	-   problemie pierwiastka dyskretnego
	-   losowych kluczach szyfrujących 
	-   problemie faktoryzacji +
	-   złożoności algorytmu szyfrującego
10. W kryptografii asymetrycznej używamy:
	-   dwóch różnych kluczy symetrycznych
	-   pary kluczy prywatnego i publicznego każdego użytkownika
	-   klucza prywatnego oraz wielu kluczy publicznych +
	-   kluczy prywatnych innych użytkowników