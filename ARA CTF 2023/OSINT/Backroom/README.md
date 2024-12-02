# Backroom

> I found a place that give me a backroom vibes. I think I like this place, so I give this place 5 star. Can you find this place?

## Solusi Challenge

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Backroom/images/IMG20221221153220.jpg" width="20%" height="auto" />

Pada challenge diatas diberikan foto suatu tempat, kita menggunakan exiftool untuk mendapatkan GPS latitude dan GPS longitude.

```
exiftool IMG20221221153220.jpg     
```
<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Backroom/images/image-004.png" width="40%" height="auto" />

Setelah itu, kita dapat mencarinya melalui https://www.gps-coordinates.net/

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Backroom/images/image-006.png" width="70%" height="auto" />

Setelah mendapatkan lokasi dari foto tersebut, kita dapat menemukan flag dari challenge ini pada kolom ulasan Google tentang lokasi tersebut.

<img src="https://github.com/jjchoNC/ctf-writeups/blob/main/ARA%20CTF%202023/OSINT/Backroom/images/image-007.png" width="40%" height="auto" />

```
Flag :ARA2023{c4r3full_w1th_y0uR_m3tad4ta}
```
