<h1 align="center">HELP</h1>

## Deskripsi Soal
<p align="justify">Bob is receiving a message from their client, to put this text on the display in the office. Bob is confused because he didnt know what is it, Can you help him?</p>


## Solusi Challenge 
<p align="justify">Diberikan suatu attachment berupa angka biner. Challenge meminta kita agar menerjemahkan maksud dari angka-angka biner itu.</p>
<img src="https://github.com/Haalloobim/ctf-writeups/blob/main/ARA%20CTF%202023/Cryptography/Help/images/image-014.png"  width="80%" height="auto"/>

<p align="justify">Kami pikir challenge ini menggunakan binary converter biasa Namun setelah mencoba segala cara, kita mencoba mencari tool di dcode.fr dengan 
keyword “office”, tetapi tidak ada hasil yang ditemukan. Setelah membaca deskripsi soal kembali, kita mencoba mencari tool di dcdoe.fr dengan keyword “display” </p>
<img src="https://github.com/Haalloobim/ctf-writeups/blob/main/ARA%20CTF%202023/Cryptography/Help/images/image-015.png"  width="80%" height="auto"/>
<p align="justify">Kami menemukan tool dengan nama “7-segment display”  yang mana sesuai dengan list binary di attachment (7 bit tiap baris). Setelah dimasukan didapatkan hasil sebagai berikut
</p>
<img src="https://github.com/Haalloobim/ctf-writeups/blob/main/ARA%20CTF%202023/Cryptography/Help/images/image-016.png"  width="80%" height="auto"/>
<p align="justify">Kami menebak bahwa ada kata yang menyerupai kata “SUPER” yang termirror dihasil decrypt, lalu kami mencoba me reverse dengan tool di dcode.fr dan mendecrypt ulang.</p>
<img src="https://github.com/Haalloobim/ctf-writeups/blob/main/ARA%20CTF%202023/Cryptography/Help/images/image-017.png"  width="80%" height="auto"/>
<p align="justify">
Didapatkan flag yang termirror, kami menerjemahkan satu persatu dan didapatkan flag.</p>
<img src="https://github.com/Haalloobim/ctf-writeups/blob/main/ARA%20CTF%202023/Cryptography/Help/images/image-018.png"  width="80%" height="auto"/>



## Flag

```
ARA2023{supertranscendentess_it_is_hehe}
```
