# Furr(y)verse

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Furr(y)verse/images/image70.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini diberikan sebuah file ELF 64bit yang bernama
> ayojadifurry. Kami diminta untuk mendapatkan flag di dalam file
> tersebut.

## Solusi Challenge

> Langkah pertama adalah membuka file tersebut di IDApro 64 bit.
> Terlihat dari fungsi main terdapat function encodeKey dengan parameter
> key.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Furr(y)verse/images/image71.jpg" width="45%" height="auto" />
>
> Lalu kami mencari value dari key terlebih dahulu. Nilai value key
> didapatkan yaitu@ch^CN=N@um\*f+^Y/\*F+^Y/If+\>w.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Furr(y)verse/images/image72.jpg" width="45%" height="auto" />
>
> Setelah nilai key didapatkan. Kami menganalisis fungsi encodeKey().
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Furr(y)verse/images/image73.jpg" width="45%" height="auto" />
>
> Setelah itu tinggal membuat script sederhana dan didapatkan flagnya.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Furr(y)verse/images/image74.jpg" width="45%" height="auto" />
```
Flag : FindITCTF{s0l1d_50L1d_5Ol1D}
