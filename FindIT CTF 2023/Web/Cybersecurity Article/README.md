# Cybersecurity Article

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Cybersecurity%20Article/images/image51.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini kita diminta mencari flag sebuah website cybersecurity
> article dengan ip 34.124.192.13:19488.

## Solusi Challenge

> Langkah pertama kami mencoba menelusuri semua yang ada di website
> tersebut dari view source, element, sampai application. Kemudian pada
> tab application terdapat sebuah cookie dengan key flag dan value
> cfcd208495d565ef66e7dff9f98764da setelah itu menggunakan
> dcode.fr/md5-hash kami mendapatkan hasil dekripsi berupa angka 0,
> sehingga kami mencoba meng encrypt angka 1 menjadi md5
> (c4ca4238a0b923820dcc509a6f75849b).
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Cybersecurity%20Article/images/image52.jpg" width="45%" height="auto" />
>
> Setelah value cookie diubah dengan c4ca4238a0b923820dcc509a6f75849b
> halaman akan ter redirect ke halaman baru jika kita lihat pada
> tabreponse pada burpsuite, dapat ditemukan flag part 1 (base64 decode
> =\> FindITCTF{), flag part2 dan hint untuk flag part 3 (base64 =\>
> ju5t_s0me\_ Note: for the 3rd part maybe this page have some OPTIONS to
> you!)
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Cybersecurity%20Article/images/image55.jpg" width="45%" height="auto" />
>
> 
>
> Untuk flag ketiga sesuai petunjuk sebelumnya, ubah request method ke
> options maka akan didapatkan flag part3 dan hint (base64
> =\>r36ul4R_w3b\_ Note: for the 4th part i think u should HEAD to this
> page).
> 
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Cybersecurity%20Article/images/image56.jpg" width="45%" height="auto" />
>
> Dengan mengubah request method ke HEAD sesuai hint sebelumnya maka flag
> part akhir didapatkan (base64 =\> 3xplo1tat1on_r1ght?})
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Web/Cybersecurity%20Article/images/image57.jpg" width="45%" height="auto" />

Flag : FindITCTF{ju5t_s0me\_ r36ul4R_w3b\_ 3xplo1tat1on_r1ght?}
