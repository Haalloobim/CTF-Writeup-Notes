# Find IT

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Find%20IT/images/image58.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini kita diminta mencari flag pada 34.124.192.13:5009.

## Solusi Challenge

> Langkah pertama yang terpikir yaitu melakukan view source dan
> didapatkan flag part 1 (FindITCTF{f1nd_tH3\_).
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Find%20IT/images/image59.jpg" width="45%" height="auto" />
>
> Setelah itu kami membuka chrome dev tools pada tab Network. Dan
> mendapatkan flag kedua pada style.css (c0mM0n\_)
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Find%20IT/images/image60.jpg" width="45%" height="auto" />
>
> Dan flag part ketiga pada script.js (un53cure3\_).
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Find%20IT/images/image61.jpg" width="45%" height="auto" />
>
> Flag part 4 kami menemukan di cookie (Pl4C35_t0_h1d3\_).
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Find%20IT/images/image62.jpg" width="45%" height="auto" />
>
> Dan flag part akhir ditemukan pada https://ctf.find-it.id/robots.txt.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Find%20IT/images/image63.jpg" width="45%" height="auto" />

```
Flag :
FindITCTF{f1nd_tH3_c0mM0n_un53cure3_Pl4C35_t0_h1d3_5tuFf_r16ht}
