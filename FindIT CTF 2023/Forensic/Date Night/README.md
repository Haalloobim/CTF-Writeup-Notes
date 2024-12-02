<h1 align="center">Date Night</h1>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Forensic/Date%20Night/Files/1.png" width="45%" height="auto" />
</p>

## Deskripsi Challenge

<p align="justify">Pada chall ini diberikan sebuah file  .docx yang bernama challenge.docx dan kami disuruh untuk menganalisis.   </p>

## Solusi Challenge

<p align="justify">Setelah file dibuka ditemukan banyak foto didalam file .docx yang ada. Kami lakukan binwalk untuk mengekstrak semua fotonya. </p>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Forensic/Date%20Night/Files/2.png" width="70%" height="auto" />
</p>

<p align="justify">Karena file yang diesktrak sangat banyak. Kami melakukan recursive grep sesuai dengan format flag yang ada. Flag didapatkan di file image12.jpg..  </p>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Forensic/Date%20Night/Files/3.png" width="70%" height="auto" />
</p>


```
Flag : FindITCTF{j4lan_bar3ng_ay4ng_739397} 
