# Hey detective, can you help me

> Ada seorang cosplayer dari China yang sangat aktif bersosial media, dia kadang memposting foto cosplaynya di facebook dan instagram. Dia pernah berkuliah di universitas ternama di China, suatu saat dia dan temannya berkunjung pada toko boneka untuk membeli sebuah boneka, tidak lupa dia juga berfoto dengan sebuah maskot di sana. Lalu selanjutnya dia mampir ke sebuah toko buku untuk membeli buku, sebagai seseorang yang update sosial media dia juga mengambil sebuah foto di toko buku tersebut dengan pose terduduk. Ohh iya dia juga pernah berfoto bareng atau collab dengan cosplayer asal China dengan nama 'Sakura'.

## Solusi

Salah satu dari anggota tim kami teringat pernah melihat video yang disajikan pada challenge tersebut, dan teringat dengan kata kunci kenko yang merujuk pada cosplayer tersebut.


Setelah mencari pada sosial media instagram, ternyata benar bahwa cosplayer tersebut bernama “Yanzikenko”, dan kami juga berhasil menemukan video yang diberikan oleh panitia pada akun Instagram kenko.

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Hey%20detective%2C%20can%20you%20help%20me/images/image-009.png" width="40%" height="auto" />

kemudian kami menggunakan tool https://commentpicker.com/instagram-user-id.php) untuk mencari User ID pada instagram dia dan menemukan bahwa ID nya adalah “44793134117”

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Hey%20detective%2C%20can%20you%20help%20me/images/image-010.png" width="20%" height="auto" />

Setelah mencari pada akun Instagram nya kami tidak menemukan hal hal yang terkoneksi dengan deskripsi soal, oleh karena itu kami berpindah ke facebook. Pada facebook kami berusaha mencari post kenko yang berhubungan dengan Universitas, Toko Buku, dan Toko Boneka, setelah scroll scroll facebook kami mendapatkan post yang berhubungan dengan hal tersebut antara lain sebagai berikut:

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Hey%20detective%2C%20can%20you%20help%20me/images/image-011.png" width="40%" height="auto" />

**Gambar 1**

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Hey%20detective%2C%20can%20you%20help%20me/images/image-012.png" width="40%" height="auto" />

**Gambar 2**

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Hey%20detective%2C%20can%20you%20help%20me/images/image-013.png" width="40%" height="auto" />

**Gambar 3**

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Hey%20detective%2C%20can%20you%20help%20me/images/image-014.png" width="40%" height="auto" />

**Gambar 4**

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Hey%20detective%2C%20can%20you%20help%20me/images/image-015.png" width="40%" height="auto" />

**Gambar 5**

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Hey%20detective%2C%20can%20you%20help%20me/images/image-016.png" width="20%" height="auto" />

**Gambar 6**

Pada Gambar 1 ditemukan post dari kenko bahwa dia mengunjungi Toko buku dengan posisi duduk, dapat dilihat pada gambar tersebut ditunjukkan waktu upload nya adalah 3Juni2019-10:25, kemudian pada Gambar 2 dan 3, ditemukan juga post kenko sedang berfoto pada toko boneka dengan maskot tersebut, kemudian kami mencari foto maskot tersebut dengan menggunakan google lens dan menemukan nama maskot nya adalah Molly, setelah itu pada gambar 4 kami mencari kata “Flag” pada akun dari kenko di facebook dan menemukan sebuah komentar dari user yang menyatakan flag tersebut yang berbunyi Y0u4r3ThE0s1nTm45t3R, dan yang terakhir adalah universitas dari kenko yang dapat ditemukan pada postingan facebook kenko (pada gambar 6) yang berada pada Beijing Normal University yang dapat disingkat BNU. Untuk mensubmit flag kami menggabungkan segala hal yang telah kami dapatkan dan flag terakhir adalah

```
Flag: ARA2023{44793134117_BNU_Molly_3Juni2019-10:25_Y0u4r3ThE0 s1nTm45t3R}
```
