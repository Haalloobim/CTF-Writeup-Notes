<h1 align="center">Lost</h1>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Lost/Files/1.png" width="45%" height="auto" />
</p>

## Deskripsi Challenge

<p align="justify">Pada chall ini kita diminta untuk mencari suatu file yang hilang pada website <a href="https://www.find-it.id">find-it.id</a> pada rentang waktu di tahun 2023. </p>

## Solusi Challenge

<p align="justify">Karena diminta untuk mencari sebuah file yang hilang pada suatu website di masa lalu, kami menggunakan bantuan website <a href="https://archive.org/web/">Wayback Machine</a>.  Dan mencari web findit pada web tersebut. </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Lost/Files/2.png" width="75%" height="auto" />
</p>

<p align="justify">Pada website wayback machine, terdapat beberapa perubahan yang terjadi pada website findit yang ditandai dengan lingkaran hijau. Setelah berjalan jalan dan mengunjungi semua lingkaran hijau, kami menemukan sebuah kejanggalan pada website pada tanggal 28 Maret 2023. </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Lost/Files/3.png" width="75%" height="auto" />
</p>

<p align="justify">Ketika kami meng inspect website tersebut terdapat sebuah script dari javascript yang memunculkan kalimat “Apa tu kira kira” dan kami segera mendownload file tersebut dan membuka filenya yang bernama <strong>mongo-secret.js</strong>. </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Lost/Files/4.png" width="75%" height="auto" />
</p>

<p align="justify">Setelah membuka file tersebut terdapat dua variabel yang mencurigakan, yang pertama adalah strings yang di encrypt dengan base64, yang kedua adalah sebuah link youtube. </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Lost/Files/5.png" width="75%" height="auto" />
</p>

<p align="justify">Karena terdapat strings yang di encrypt dengan base64 maka kami memutuskan untuk men decrypt dengan tool <a href="https://www.dcode.fr/base-64-encoding">dcode.fr</a> dan mendapatkan flag nya seperti berikut: </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Lost/Files/6.png" width="75%" height="auto" />
</p>

```
Flag : FindITCTF{d1git4l_f00tpr1nt_i5_s0_u53fu1_r1ght?}
