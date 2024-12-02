# Randomized Seed

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/Randomized%20Seed/imagae/image18.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini diberikan 2 file yang diantaranya adalah file out.txt
> yang dimana sebuah strings yang telah di encrypt dan juga sebuah file
> challenge.py yang dimana merupakan sebuah script untuk menencrypt
> sebuah strings tersebut.
>
> Kami disuruh untuk berusaha men decrypt strings tersebut.

## Solusi Challenge

> Mula mula kami menganalisis program python yang disertakan pada chall
> ini. Program mengenkripsi isi dari file 'flag.txt' menggunakan metode
> XOR dengan angka acak. Enkripsi dilakukan dengan mengubah setiap
> karakter dalam teks flag menjadi representasi hexadesimal dari hasil
> operasi XOR antara karakter tersebut dengan angka acak dalam rentang 0
> hingga 255. Untuk melakukan dekripsi terhadap teks yang dihasilkan,
> perlu dilakukan operasi XOR antara setiap karakter dalam teks
> terenkripsi dengan angka acak yang sama yang digunakan saat enkripsi.
> Kami membuat program dalam python untuk membantu dalam menyelesaikan
> chall ini sebagai berikut.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/Randomized%20Seed/imagae/image19.jpg" width="45%" height="auto" />
>
> Program ini mencoba melakukan dekripsi dengan menggunakan berbagai
> nilai seed secara berurutan. Dekripsi dilakukan dengan mengoperasikan
> setiap byte dalam teks terenkripsi dengan operasi XOR menggunakan
> angka acak dalam rentang 0 hingga 255. Jika hasil dekripsi
> menghasilkan teks yang dapat dicetak, maka seed yang digunakan dan
> teks terdekripsinya akan dicetak. Berikut adalah hasil jika program
> dijalankan.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/Randomized%20Seed/imagae/image20.jpg" width="45%" height="auto" />
>
```
Flag : FindITCTF{2_Ez_t0_Br3ak_27431}
