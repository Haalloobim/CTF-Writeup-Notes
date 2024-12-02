# Choo-Choo

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/Choo-Choo/image/image11.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini kita diberikan sebuah script .cpp yang berisi fungsi
> enkripsi dan file .txt yang berisi encrypted flag.

## Solusi Challenge

> Kami mencari key dengan menambah setiap digit pada 2023. 2 + 0 + 2 + 3
> = 7 = key. Karena pada deskripsi soal disebutkan “What did **Thomas
> the Train** hide?” sehingga kami menganggap ini adalah rail fence
> cipher. Dan setelah mencoba melalui dcode.fr didapatkan flag.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/Choo-Choo/image/image12.jpg" width="45%" height="auto" />

```
Flag : FindITCTF{r41LF3Nc3_C0d3_1s_E4sy}
