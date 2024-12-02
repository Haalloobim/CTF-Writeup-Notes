# Mental Health Check

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Other/Mental%20Health%20Check/images/image64.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini diberikan sebuah file .exe yang bernama
> mentalhealtcheck.exe dan kami disuruh untuk menganalisis.

## Solusi Challenge

> Karena mendapati file yang diberikan merupakan file yang berekstensi
> .exe maka kami langsung mencoba untuk melakukan commands strings pada
> file tersebut dengan payload seperti berikut :
>
> “strings mentalhealthcheck.exe \| grep FindITCTF{“
>
> Dan mendapatkan flagnya.
>
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Other/Mental%20Health%20Check/images/image65.jpg" width="60%" height="auto" />

```
FindITCTF{everyone_asks_who_are_you_but_not_how_are_you}
