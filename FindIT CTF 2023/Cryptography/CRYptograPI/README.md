# CRYptograPI

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/CRYptograPI/image/image27.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini diberikan sebuah file .txt yang berisikan encoded flag.
> Kami diminta untuk men decrypt encrypted flag tersebut.

## Solusi Challenge

> Encrypted flag yang diberikan di message.txt berformat hex sehingga
> perlu untuk di unhex ke bentuk desimal terlebih dahulu. Dideskripsi
> chall juga dapat dipahami bahwa encrypted flag merupakan hasil dari
> operasi bitwise dengan tiap digit desimal pada pi (141……….) dalam
> ASCII. Karena pada chall crypto umumnya operasi bitwise yang digunakan
> untuk dekripsi adalah XOR, maka kami menggunakan XOR dalam
> penyelesaian chall ini.
>
> Berikut adalah program C++ yang kami buat.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/CRYptograPI/image/image28.jpg" width="auto" height="30%" />
>
> Dan berikut adalah outputnya jika program dijalankan.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/CRYptograPI/image/image29.png" width="auto" height="45%" />

```
Flag : FindITCTF{s3b4IKnY4_j4n9An_T3rl4lU_9Eg4B4h}
