# Шифр RSA

## Что это за шифр?

RSA (Rivest–Shamir–Adleman) - это один из первых криптографических алгоритмов с открытым ключом, который используется для безопасной передачи данных. Алгоритм основан на сложности факторизации произведения двух больших простых чисел. В данной реализации используются базовые функции для генерации ключей, шифрования и дешифрования сообщений.

## Как он работает?

1. **Генерация ключей**: Алгоритм генерирует пару ключей - публичный и приватный. Публичный ключ используется для шифрования сообщений, а приватный - для их дешифрования.
2. **Шифрование**: Сообщение преобразуется в числовую форму, затем каждый символ сообщения возводится в степень, равную публичному ключу, и вычисляется по модулю произведения двух простых чисел.
3. **Дешифрование**: Зашифрованное сообщение обрабатывается приватным ключом, чтобы восстановить исходное сообщение.

## Подробные шаги:

#### Генерация ключей:

- Генерируются два случайных простых числа `p` и `q`.
- Вычисляется модуль `n` как произведение `p` и `q`.
- Вычисляется функция Эйлера `φ(n)` как `(p-1)*(q-1)`.
- Генерируется публичный экспонент `e` (обычно используется 65537).
- Вычисляется приватный ключ `d` как модульная обратная величина `e` по модулю `φ(n)`.

#### Шифрование:

- Сообщение преобразуется в числовую форму.
- Каждый символ возводится в степень `e` и вычисляется по модулю `n`.

#### Дешифрование:

- Каждый зашифрованный символ возводится в степень `d` и вычисляется по модулю `n` для восстановления исходного символа.

## Пример вывода
- Шифр RSA
- Длина ключа: `16 бит`
- Публичный ключ: `(65537, 39917)`
- Приватный ключ: `(9461, 39917)`

- Введите сообщение для шифрования: `привет мир`
- Коды символов сообщения: `[1087, 1088, 1080, 1074, 1077, 1090, 32, 1084, 1080, 1088]`
- Зашифрованное сообщение:
`['3663', '16617', '19426', '33115', '14515', '21371', '19788', '23362', '19426', '16617']`
- Расшифрованное сообщение:
`привет мир`
