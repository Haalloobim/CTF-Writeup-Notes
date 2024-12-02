# Confusing Encryption

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/Confusing Encryption/image/image21.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini diberikan 2 file yang diantaranya adalah file
> encrypted.txt yang dimana sebuah strings yang telah di encrypt dan
> juga sebuah file enc.py yang dimana merupakan sebuah script untuk
> menencrypt sebuah strings tersebut.
>
> Kami disuruh untuk berusaha men decrypt strings tersebut.

## Solusi Challenge

> Mula mula kami melakukan pada program Python yang digunakan untuk
> melakukan enkripsi pada flag dengan sebuah kunci acak. Dalam
> prosesnya, flag diubah menjadi representasi heksadesimal, kemudian
> dibuat kunci acak dalam bentuk heksadesimal dengan panjang yang sama
> dengan flag. Kedua nilai ini kemudian di-XOR dan hasilnya disimpan
> dalam bentuk heksadesimal ke dalam file 'encrypted.txt'. Kemudian kami
> membuat program Python yang dirancang untuk mendekripsi teks cipher
> yang dihasilkan oleh program enkripsi sebelumnya dengan melakukan
> brute force pada angka seed yang digunakan dalam fungsi random_hex.
> Program akan mencoba setiap kemungkinan seed dalam rentang random_N(1)
> hingga random_N(6)+1 untuk menghasilkan kunci, lalu melakukan operasi
> XOR pada teks cipher dengan kunci tersebut. Jika hasil dekripsi
> diawali dengan 'FindITCTF' dalam format heksadesimal, program mencetak
> flag dan berhenti melakukan brute force. Berikut adalah program yang
> kami buat termasuk outputnya jika input adalah
>
> “3a1d15719101552d27e307dd6a07439d9665b6413384560a092bee5c05907ad8
> 5b7fc5a1b66a5450997dae2159f35068f9ca”.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/Confusing Encryption/image/image22.jpg" width="45%" height="auto" />
> 

```
Flag : FindITCTF{ju5t_x0R_kn0wn_pl4in_t3xt_4ttack_r1ght?}
