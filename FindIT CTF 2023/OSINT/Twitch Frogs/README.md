<h1 align="center">Twitch Frogs</h1>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Twitch%20Frogs/Files/1.png" width="45%" height="auto" />
</p>

## Deskripsi Challenge

<p align="justify">Pada chall ini kita diminta untuk mencari sebuah pesan yang dikirimkan oleh sebuah user di twitch “dundorma” ke sebuah channel twitch yang bernama “xqc”. Pada rentang waktu 2017 - 2023.  </p>

## Solusi Challenge

<p align="justify">Karena diminta untuk mencari sebuah pesan pada twitch kami mencari sebuah tools untuk mengcrawl sebuah chat yang ada di Twitch dan kami menemukan sebuah tool yaitu <a href="https://logs.ivr.fi/">justlog</a>. Pada website tersebut disuruh untuk memasukkan sebuah user dan channel yang akan dituju oleh karena itu kami memasukkan user dan channelnya. </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Twitch%20Frogs/Files/2.png" width="75%" height="auto" />
</p>

<p align="justify">Dan muncul sebuah list tanggal user mengechat pada channel tersebut.  </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Twitch%20Frogs/Files/3.png" width="75%" height="auto" />
</p>

<p align="justify">Setelah berjalan jalan menyusuri semua tanggal yang ada akhirnya kami menemukan sebuah pesan yang mengandung sebuah Flag pada bulan 1 di tahun 2023. </p>

<p align="center">
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/OSINT/Twitch%20Frogs/Files/4.png" width="75%" height="auto" />
</p>


```
Flag : FindITCTF{ju5t_a_regul4r_twitch_chatter}
