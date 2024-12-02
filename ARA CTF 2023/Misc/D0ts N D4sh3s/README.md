# D0ts N D4sh3s

> Albert was lost in a deep forest surrounded by a sea and tried to escape by sending a SOS signal containing a code.

Jack who works at a lighthouse realized that someone was sending a SOS signal and responses as fast as he can.

What do you think Albert tries to say?

## Solusi

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/Misc/D0ts%20N%20D4sh3s/images/image-007.png" width="70%" height="auto" />

Kemudian kami menggunakan tool online yaitu (https://gchq.github.io/CyberChef/) untuk mendecrypt pesan tersebut dari morse code menjadi flag, dan menggunakan resep seperti dibawa ini.

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/Misc/D0ts%20N%20D4sh3s/images/image-008.png" width="70%" height="auto" />

Kami menggunakan rumus from morse code dan from binary karena ketika men decrypt morse code flag nya masih berupa binary, dan flag akhir ditemukan.

```
Flag :ARA2023{!ts_ju5t_4_m0rs3_aft312_a1!}
```