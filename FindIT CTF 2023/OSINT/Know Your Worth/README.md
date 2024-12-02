<h1 align="center">Know Your Worth</h1>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Know%20Your%20Worth/Files/1.png" width="45%" height="auto" />
</p>

## Deskripsi Challenge

<p align="justify">Pada chall ini diminta untuk menentukan nama perusahaan, ticker, dan kota headquarters dari 2 buah gambar yang sepertinya adalah gambar dari grafik saham sebagai berikut.  </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Know%20Your%20Worth/Files/2.png" width="75%" height="auto" />
</p>

## Solusi Challenge

<p align="justify">Mula mula kami cari gambar chall2 pada <a href="https://lens.google/">google lens</a> kemudian muncul hasil penelusuran sebagai berikut. </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Know%20Your%20Worth/Files/3.png" width="75%" height="auto" />
</p>

<p align="justify">Setelah ditelusuri lebih lanjut kami temukan bahwa grafik tersebut merupakan grafik dari saham GameStop.  </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Know%20Your%20Worth/Files/4.png" width="75%" height="auto" />
</p>

<p align="justify">Kemudian kami melakukan penelusuran dengan keyword “GameStop” dan muncul hasil sebagai berikut. </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Know%20Your%20Worth/Files/5.png" width="75%" height="auto" />
</p>

<p align="justify">Jika diamati pada bagian ini, maka semua informasi yang dibutuhkan pada flag sudah tersedia.</p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Know%20Your%20Worth/Files/6.png" width="75%" height="auto" />
</p>

```
Flag : FindITCTF{gamestop_GME_grapevine}
