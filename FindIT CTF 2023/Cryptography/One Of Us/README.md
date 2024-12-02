# One Of Us

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/One%20Of%20Us/image/image23.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini diberikan encrypted text dan juga script enkripsi
> dengan python. Kami diminta untuk meng enkripsi frasa "HAPPY SWEET
> SEVENTEEN FREDDIE".

## Solusi Challenge

> Pada attachments terdapat encrypted text yang apabila di decrypt
> dengan vigenere decoder akan menghasilkan output sebagai berikut.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/One%20Of%20Us/image/image24.jpg" width="60%" height="auto" />
>
> Nampak bahwa key yang paling sesuai adalah “BDBCFDA”, karena hasil
> decrypt dengan key tersebut akan menghasilkan output yang paling
> sesuai dan dapat dibaca.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/One%20Of%20Us/image/image25.jpg" width="60%" height="auto" />
>
> Kemudian kami melihat pada file new_encoder.py terdapat sebuah
> komentar pada akhir program nya seperti berikut.
>
> ''' so you have found the key... but it's not as simple as that.
>
> the new key is the old one in reverse + 2021530 and i think the
> encoder is slightly broken, oops '''
>
> Karena key yang diperoleh sebelumnya adalah “BDBCFDA” setelah diinvert
> maka akan menjadi “ADFCBDB”. Kemudian ditambah dengan 2021530, disini
> maksudnya ditambah adalah dengan memajukan alfabet setiap huruf
> berdasarkan angka yang sesuai sebagai berikut.
>
> A + 2 = C
>
> D + 0 = D
>
> F + 2 = H
>
> C + 1 = D
>
> B + 5 = G D + 3 = G
>
> B + 0 = B
>
> Sehingga key baru yang telah diperoleh adalah “CDHDGGB”. Kemudian
> langkah terakhir adalah dengan melakukan enkripsi pada "HAPPY SWEET
> SEVENTEEN FREDDIE" dengan vigenere cipher.
> 
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Cryptography/One%20Of%20Us/image/image26.jpg" width="60%" height="auto" />>
> 
> Hasil dari enkripsinya adalah "JDWSE YXGHA VKBFPWLHT LSGGKLK".
>
> Sehingga diperoleh flag untuk chall ini sebagai berikut.
>
```
Flag : FindITCTF{JDWSE_YXGHA_VKBFPWLHT_LSGGKLK}
