<h1 align="center">Been There Done That</h1>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Forensic/Been%20There%20Done%20That/Files/1.png" width="45%" height="auto" />
</p>

## Deskripsi Challenge

<p align="justify">Pada chall ini diberikan sebuah file  yang bernama crashed1 dan kami disuruh untuk menganalisis.  </p>

## Solusi Challenge

<p align="justify">Ini memecahkan chall ini langkah pertama kami yaitu melihat metadata. Setelah itu, kami mendapatkan bahwa terdapat GPS Position. </p>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Forensic/Been%20There%20Done%20That/Files/2.png" width="45%" height="auto" />
</p>

<p align="justify">Tinggal dicari lokasi dari data GPS position yang didapat. Setelah dicari didapatkan flag yang berupa nama suatu lokasi.  </p>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Forensic/Been%20There%20Done%20That/Files/3.png" width="45%" height="auto" />
</p>


```
Flag : FindITCTF{Gunung_Tangkuban_Parahu}
