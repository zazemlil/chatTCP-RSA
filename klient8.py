import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

ClientSocket = socket.socket()
host = '25.13.44.156'
port = 5141

print('Waiting for connection')
try:
    ClientSocket.connect((host, port))
except socket.error as e:
    print(str(e))

# Получаем имя пользователя от пользователя
username = input('Введите ваше имя: ')

# Отправляем имя пользователя на сервер
ClientSocket.send(username.encode())

# Получаем публичный ключ от сервера
server_public_key = ClientSocket.recv(4096)

# Генерируем AES ключ для шифрования сообщений
encryption_key = get_random_bytes(16)

# Зашифровываем ключ шифрования с помощью серверного публичного ключа
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(server_public_key))
encrypted_encryption_key = cipher_rsa.encrypt(encryption_key)

# Отправляем зашифрованный ключ шифрования на сервер
ClientSocket.send(encrypted_encryption_key)

# Получаем подтверждение от сервера
response = ClientSocket.recv(1024).decode()
print(response)


def encrypt_message(message):
    cipher_aes = AES.new(encryption_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
    return cipher_aes.iv + ciphertext


def decrypt_message(ciphertext):
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher_aes = AES.new(encryption_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()


def receive_messages():
    while True:
        try:
            # Принимаем зашифрованное сообщение от сервера
            encrypted_message = ClientSocket.recv(1024)
            decrypted_message = decrypt_message(encrypted_message)
            print(decrypted_message)
        except ConnectionResetError:
            # Если соединение с сервером было сброшено, выходим из цикла
            print('Соединение с сервером разорвано.')
            break


def send_message():
    while True:
        try:
            # Отправляем сообщение на сервер
            recipient = input('Введите получателя:\n')
            if '!users' in recipient:
                encrypted_recipient = encrypt_message(recipient)
                ClientSocket.send(encrypted_recipient)
            else:
                message = input('Введите сообщение:')
                full_message = f'{recipient}:{message}'
                encrypted_message = encrypt_message(full_message)
                ClientSocket.send(encrypted_message)
        except ValueError:
            print('Ошибка: неверный формат ввода.')


receive_thread = threading.Thread(target=receive_messages)
send_thread = threading.Thread(target=send_message)

receive_thread.start()
send_thread.start()
