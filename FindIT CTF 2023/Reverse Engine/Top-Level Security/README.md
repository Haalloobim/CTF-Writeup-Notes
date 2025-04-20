# Top-Level Security

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Top-Level%20Security/images/image75.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini diberikan sebuah file .exe dengan nama chall.exe. Kami
> diminta untuk mecari flag didalamnnya.

## Solusi Challenge

> Langkah pertama adalah membuka file tersebut di IDApro 32bit. Setelah
> itu kami melakukan view strings (Karena coba view pseudocode ga bisa
> 🙁).
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Top-Level%20Security/images/image76.jpg" width="45%" height="auto" />
>
> Terlihat sangat banyak strings yang berformat seperti flag. Tapi kami
> menemukan kejanggalan pada satu strings (\*OHUNL \[OL l;u7l Z\[YPUN
> \[V l3u\>l Z\[YPUN). Setelah mencoba bruteforce ROT dekrips melalui
> dcode.fr. Didapati satu hasil yang paling masuk akal.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Top-Level%20Security/images/image77.jpg" width="45%" height="auto" />
>
> Setelah itu kami menemukan strings “Correct Password” yang dibawahnya
> terdapat juga string dengan value
>
> FindITCTF{T0P_L3v3L_S3cUr1Ty_1s_3a5y}.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Top-Level%20Security/images/image78.jpg" width="45%" height="auto" />
>
> Dengan mengganti kata ‘T0P’ dengan ‘L0W’ seperti pada hasil dekrips
> ROT.

```
Flag : FindITCTF{L0W_L3v3L_S3cUr1Ty_1s_3a5y}
