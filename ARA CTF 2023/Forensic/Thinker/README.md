# Thinker

> I always overthink about finding other part of myself, can you help me?

## Solusi

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/Forensic/Thinker/images/image-001.png" width="20%" height="auto" />

Langkah pertama yang dilakukan adalah mengekstrak file dan folder yang disematkan kedalam foto menggunakan ```binwalk -e confused.png```

Setelah itu, buka file e.txt dan decrypt value yang ada didalamnya menggunakan operation to from base64 pada [CyberChef].

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/Forensic/Thinker/images/image-002.png" width="60%" height="auto" />

Didaptkan **flag part1 (ARA2023{)**,  lalu ekstrak find.zip dan decrypt value yang ada pada a.txt dengan operation from HEX pada [CyberChef].

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/Forensic/Thinker/images/image-003.png" width="60%" height="auto" />

Didapatkan **flag part2(5!mpl3\_)**. Selanjutnya extrace something.zip dan decrypt binary yang ada pada s.txt dengan operation from binary pada [CyberChef].

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/Forensic/Thinker/images/image-004.png" width="60%" height="auto" />

Didapatkan **flag part 3(C0rrupt3d\_)**. Selanjutnya extrace supicious.zip dan perbaiki file y.png yang corrupt dengan mengedit 16 bytes hex awal.

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/Forensic/Thinker/images/image-005.png" width="60%" height="auto" />

Buka foto dan decrypt angka -angka yang ada pada y.png dengan menggunakan operation from decimal pada [CyberChef].

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/Forensic/Thinker/images/image-006.png" width="60%" height="auto" />

Jika semua part flag disusun akan membentuk flag yang lengkap.

```
Flag: ARA2023{5!mpl3_C0rrupt3d_1m4ge5}
```

[CyberChef]:https://gchq.github.io/CyberChef/
