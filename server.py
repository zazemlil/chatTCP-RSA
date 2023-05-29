import socket
import os
from _thread import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

ServerSocket = socket.socket()
host = '25.13.44.156'
port = 5141

try:
    ServerSocket.bind((host, port))
except socket.error as e:
    print(str(e))

ServerSocket.listen(5)
users = {}
print('Waiting for a Connection..')

def threaded_client(connection, address):
    # Принимаем имя пользователя от клиента
    username = connection.recv(1024).decode()
    print(f'Новый пользователь подключился: {username} ({address[0]}:{address[1]})')
    
    # Генерируем ключевую пару RSA
    key_pair = RSA.generate(2048)
    public_key = key_pair.publickey().export_key()
    
    # Отправляем публичный ключ клиенту
    connection.send(public_key)
    
    # Принимаем зашифрованный ключ шифрования от клиента
    encrypted_encryption_key = connection.recv(4096)
    
    # Расшифровываем ключ шифрования с помощью своего приватного ключа
    cipher_rsa = PKCS1_OAEP.new(key_pair)
    encryption_key = cipher_rsa.decrypt(encrypted_encryption_key)
    
    # Регистрируем пользователя
    users[username] = {
        'connection': connection,
        'encryption_key': encryption_key
    }
    
    # Отправляем подтверждение клиенту
    connection.send('Вы успешно зарегистрированы на сервере.'.encode())
    
    while True:
        try:
            # Принимаем зашифрованное сообщение от клиента
            encrypted_message = connection.recv(1024)
            decrypted_message = decrypt_message(encrypted_message, encryption_key)
            
            if decrypted_message == '!users':
                # Если клиент запросил список пользователей, отправляем ему список
                online_users = ', '.join(users.keys())
                encrypted_response = encrypt_message(f'Пользователи в сети: {online_users}', encryption_key)
                connection.send(encrypted_response)
            else:
                # Иначе, ищем адресата и отправляем ему зашифрованное сообщение
                recipient, message = decrypted_message.split(':',1)
                if recipient in users:
                    print(f'Отправитель: {username}, Получатель: {recipient}, Сообщение: {decrypted_message}, Зашифрованное сообщение: {encrypted_message}')
                    recipient_connection = users[recipient]['connection']
                    encrypted_message = encrypt_message(f'Сообщение от {username}: {message}', users[recipient]['encryption_key'])
                    recipient_connection.send(encrypted_message)
                else:
                    encrypted_response = encrypt_message(f'Ошибка: пользователь {recipient} не в сети.', encryption_key)
                    connection.send(encrypted_response)
        except ConnectionResetError:
            # Если соединение с клиентом было сброшено, удаляем пользователя из списка
            print(f'Пользователь отключился: {username} ({address[0]}:{address[1]})')
            del users[username]
            break

def encrypt_message(message, key):
    cipher_aes = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
    return cipher_aes.iv + ciphertext

def decrypt_message(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

while True:
    Client, address = ServerSocket.accept()
    start_new_thread(threaded_client, (Client, address))

