# Discovered

<p align="center">
<img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Other/Discovered/images/image66.jpg" width="45%" height="auto" />
</p>

## Deskripsi Challenge

> Pada chall ini kami diberikan sebuah file pdf yang bernama secret.

## Solusi Challenge

> Karena mendapati file yang diberikan merupakan file pdf yang terdapat
> password untuk membuka filenya, maka kami memutuskan untuk me brute
> force dengan wordlist rockyou.txt dan menggunakan tool pdfcrack dengan
> payload berikut:
> ```
> “pdfcrack -f secret.pdf -w /home/bitici16/wordlist/rockyou.txt”
> ```
> 
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Other/Discovered/images/image67.jpg" width="60%" height="auto" />
>
> Dan menemukan password yang benar yaitu : “LimitedEdition”. Ketika
> Memasukkan passwordnya dan terdapat emoji emoji berikut:
> 
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Other/Discovered/images/image68.png" width="60%" height="auto" />
>
> Ketika melihat emoji emoji ini, kami langsung mencari list emoji pada
> google dan menemukan web berikut:
> <u>[Emoji](https://unicode.org/emoji/charts/full-emoji-list.html)
> [list](https://unicode.org/emoji/charts/full-emoji-list.html)</u> dan
> mencocokkan dengan list tersebut dan menemukan sebuah pattern yaitu
> setiap emoji diganti dengan huruf depan dari nama masing masing emoji
> yang ada seperti contohnya adalah
> 
> <img align="center" src="https://github.com/jjchoNC/ctf-writeups/blob/main/FindIT%20CTF%202023/Other/Discovered/images/image69.jpg" width="60%" height="auto" />
>
> Karena list tersebut maka emoji pertama digantikan dengan huruf n dan
> seterusnya dan menjadi sebuah flag yaitu:

```
Flag : FindITCTF{not_an_emot_cipher_only_need_to_find_the_pattern}
