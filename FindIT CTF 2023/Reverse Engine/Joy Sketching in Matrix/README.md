# Joy Sketching in the Matrix

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Joy%20Sketching%20in%20Matrix/images/image82.jpg" width="45%" height="auto" />
</p>
## Deskripsi Challenge

> Pada chall ini diberikan dua file, yaitu file chall yang beri
> value-value hex dan cmd.txt yang kami duga sebagai command yang mana u
> = up; l = left; r = right; d = down.

## Solusi Challenge

> Langkah pertama saya mencoba mendecrypt file chall yang berisi
> value-value hex tadi
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Joy%20Sketching%20in%20Matrix/images/image83.jpg" width="45%" height="auto" /><img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Joy%20Sketching%20in%20Matrix/images/image84.jpg" width="45%" height="auto" />
>
> Kami menduga itu adalah script arduino. Karena kami tidak bisa
> menggunakan Arduino sehingga kami memanfaatkan cmd.txt yang dijalankan
> pada python dengan bantuan modul turtle agar gambar sesuai command bisa
> terlihat.
>
> <img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Joy%20Sketching%20in%20Matrix/images/image85.jpg" width="30%" height="auto" />
> <br>
> <img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Joy%20Sketching%20in%20Matrix/images/image86.jpg" width="auto" height="200" />
>
> <img src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Reverse%20Engine/Joy%20Sketching%20in%20Matrix/images/image87.jpg" width="auto" height="200" />
```
FindITCTF{etch_the_joysketch_in_the_matrix_zwquomf}
