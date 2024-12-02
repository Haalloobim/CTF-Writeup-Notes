<h1 align="center">SH4-32</h1>

## Deskripsi Soal
<p align="center">
<img src="https://github.com/Haalloobim/ctf-writeups/blob/main/ARA%20CTF%202023/Cryptography/SH4-32/images/Capture.PNG"  width="40%" height="auto"/>
</p>
<p align="justify">Kemudian isi dari file tersebut Diberikan hash value dan wordlists, untuk memecahkan flag.</p>
<img src="https://github.com/Haalloobim/ctf-writeups/blob/37a6f1a1fabb5c78152c5cc8aaab3086bf604b24/ARA%20CTF%202023/Cryptography/SH4-32/images/image-008.png"  width="80%" height="auto"/>


## Solusi Challenge 
<p align="justify">Jika diamati secara baik pada wordlists, terdapat salah satu baris yang mencurigakan</p>
<img src="https://github.com/Haalloobim/ctf-writeups/blob/main/ARA%20CTF%202023/Cryptography/SH4-32/images/image-009.png"  width="80%" height="auto"/>
<p align="justify">Lalu tinggal kita gunakan operation from hex pada CyberChef</p>
<img src="https://github.com/Haalloobim/ctf-writeups/blob/main/ARA%20CTF%202023/Cryptography/SH4-32/images/image-010.png"  width="80%" height="auto"/>


## Flag

```
ARA2023{h4sh3d_0R_nOT_h4sh3d}
```
