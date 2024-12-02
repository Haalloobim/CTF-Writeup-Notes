<h1 align="center">CPNS</h1>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/UNITY%20CTF%202023/CPNS/Files/1.png" width="60%" height="auto" />
</p>

## Deskripsi Challenge

<p align="justify">Pada Challenge diberikan file .pcapng dan kami disuruh untuk menganalisis file tersebut apakah ada flag pada file tersebut. </p>

## Solusi Challenge

<p align="justify">Langkah pertama yang kami lakukan adalah membuka file tersebut dengan
menggunakan aplikasi wireshark yang berguna untuk menganalisis jaringan. </p>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/UNITY%20CTF%202023/CPNS/Files/2.png" width="75%" height="auto" />
</p>

<p align="justify">Kemudian seperti biasa, kami mengecek opsi export HTTP Objects dan menemukan terdapat login file pada packet 22.  </p>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/UNITY%20CTF%202023/CPNS/Files/3.png" width="75%" height="auto" />
</p>

<p align="justify">Setelah itu kami mentrace/follow packet 22 tersebut dan mendapatkan Flag berikut:  </p>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/UNITY%20CTF%202023/CPNS/Files/4.png" width="75%" height="auto" />
</p>

```
UNITY2023{5U8M1T_Y0UR_FL4G}

