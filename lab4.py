# Шифр RSA
import random
import secrets
from math import isqrt


BIT_LENGTH = 16  


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def mod_inv(a: int, m: int) -> int:
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for i in range(2, isqrt(n) + 1):
        if n % i == 0:
            return False
    return True


def generate_keypair(bits: int) -> tuple:
    def generate_prime(bits: int) -> int:
        while True:
            p = secrets.randbits(bits)
            p |= (1 << (bits - 1)) | 1  
            if is_prime(p):
                return p

    # Генерация случайных простых чисел
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    # Вычисление модуля n и функции Эйлера φ(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Генерация публичного экспонента e
    e = 65537  
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2) 

    # Генерация приватного ключа d
    d = mod_inv(e, phi)
    return ((e, n), (d, n))


def encrypt_message(message: str, public_key: tuple) -> list:
    e, n = public_key
    return [pow(ord(char), e, n) for char in message]


def decrypt_message(ciphertext: list, private_key: tuple) -> str:
    d, n = private_key
    return ''.join([chr(pow(c, d, n)) for c in ciphertext])


def main():
    print('Программа для шифрования с использованием алгоритма RSA')
    print(f'Длина ключа: {BIT_LENGTH} бит')

    public_key, private_key = generate_keypair(BIT_LENGTH)

    print(f'Публичный ключ: {public_key}')
    print(f'Приватный ключ: {private_key}')
    print()

    message = input("Введите сообщение для шифрования: ")
    print(f'Коды символов сообщения: {[ord(ch) for ch in message]}')

    encrypted = encrypt_message(message, public_key)
    print("Зашифрованное сообщение:")
    print([str(num) for num in encrypted])

    decrypted = decrypt_message(encrypted, private_key)
    print("Расшифрованное сообщение:")
    print(decrypted)


if __name__ == "__main__":
    main()
