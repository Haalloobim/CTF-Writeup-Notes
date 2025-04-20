# Bypass the Py

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Bypass%20the%20Py/images/image79.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini diberikan sebuah file .zip yang didalamnya terdapat
> executable python dan saat dibuka kita disuruh memasukkan password.

## Solusi Challenge

> Kami menggunakan pyinstxtractor untuk mengekstrak isi dari file
> Pyinstaller.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Bypass%20the%20Py/images/image80.jpg" width="45%" height="auto" />
> </p>
>
> Setelah itu, masuk ke folder hasil ekstrak dan dilakukan grep sesuai
> format flag (FindITCTF{).
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Bypass%20the%20Py/images/image81.jpg" width="45%" height="auto" />
> </p>

```
Flag : FindITCTF{t4ngl3D_w1tH_pyTh0n_4nd_5tuff}
