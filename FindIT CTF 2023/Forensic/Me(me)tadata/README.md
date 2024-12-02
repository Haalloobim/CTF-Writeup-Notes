<h1 align="center">Me(me)tadata</h1>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Forensic/Me(me)tadata/Files/1.png" width="45%" height="auto" />
</p>

## Deskripsi Challenge

<p align="justify">Pada chall ini diberikan sebuah file gambar yang bernama gambarbobi dan kami disuruh untuk menganalisis.   </p>

## Solusi Challenge

<p align="justify">Sesuai nama chal yaitu Me(me)tadata yang terlintas dipikiran kami adalah melihat metadata gambar dengan exiftool. </p>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Forensic/Me(me)tadata/Files/2.png" width="45%" height="auto" />
</p>

<p align="justify">Kami menemukan kejanggalan pada nama artist. Setelah melakukan decrypt base64 dan Hex. Kami mendapatkan flag dari chall ini.  </p>

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Forensic/Me(me)tadata/Files/3.png" width="45%" height="auto" />
</p>


```
Flag : FindITCTF{p4K3_nAny4_57291}
