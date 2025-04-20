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

