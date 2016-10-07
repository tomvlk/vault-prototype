import string
import binascii
import triplesec
import random


def decrypt(data, key):
    return triplesec.decrypt(
        data=binascii.unhexlify(data),
        key=key.encode()
    ).decode()


def encrypt(data, key):
    enc = triplesec.encrypt(
        data=data.encode(),
        key=key.encode()
    )
    return binascii.hexlify(enc)


def random_password(length):
    chars = string.ascii_letters + string.digits + '!@#$%^&*()'

    rnd = random.SystemRandom()

    return ''.join(rnd.choice(chars) for i in range(length))
