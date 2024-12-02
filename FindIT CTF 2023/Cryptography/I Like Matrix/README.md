# I Like Matrix

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/I%20Like%20Matrix/image/image15.jpg" width="30%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini kita diminta untuk men decrypt encrypted flag yang ada.

## Solusi Challenge

> Karena challnya crypto matrix dan juga terselip kata “Hill” pada
> deskripsi, jadi kami menduga bahwa ini adalah hill cipher. Karena pada
> deskripsi disebutkan “Fibonacci matrix” maka kami mulai melakukan
> dekripsi dengan fibonacci matrix sebagai berikut.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/I%20Like%20Matrix/image/image16.jpg" width="45%" height="auto" />
>
> Karena flagnya di encrypt dua kali maka perlu dilakukan decrypt sekali
> lagi. Namun jika menggunakan matriks number yang sama, flag tidak
> ditemukan.
>
> Sehingga kami menggunakan bruteforce value matriksnya.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/I%20Like%20Matrix/image/image17.jpg" width="45%" height="auto" />

```
Flag : FindITCTF{OKComPuTeR_iS_thE_bEst_AlbUum}
