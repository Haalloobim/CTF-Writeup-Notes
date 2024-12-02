# Detective Handal

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/Detective%20Handal/image/image13.jpg" width="30%" height="auto" />
</p>


## Deskripsi Challenge

> Pada chall ini kita diberi deskripsi yang mengandung berbagai hint dan
> sebuah file .txt berisi encrypted flag.

## Solusi Challenge

> Dengan membaca deskripsi soal kita tahu bahwa soal ini berhubungan dengan
> Blowfish decrypt. Clue pertama yaitu line (media sosial) dan di akhir
> deskripsi “line is an id of social media” lalu kami mencari id line
> Find IT UGM dan ditemukan pada poster promosi lomba FindIT UGM di
> instagram (ID Line : hqx0844o). Clue selanjutnya adalah IV yang
> dilanjutkan tanggal episode pertama AOT (7 April 2013 =\> 07042013).
> Lalu clue selanjutnya adalah Crash Team Racing”, kami menebak itu
> adalah mode decrypt pada blowfish. Clue selanjutnya adalah Raw dan Hex
> yang berhubungan dengan input dan output. Karen encrypted flag pada
> file mysterious_code.txt berformat HEX, maka input file HEX dan
> outputnya yang merupakan RAW. Setelah mendapatkan clue-clue yang
> mencukupi, kami melakukan decrypt di cyberchef.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/Detective%20Handal/image/image14.jpg" width="45%" height="auto" />

```
Flag : FindITCF{y0u_4r3_a_gr3at_d3tect1ve}
