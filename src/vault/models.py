
from django.contrib.auth import hashers
from django.db import models

from vault import utils


class Entry(models.Model):
    name = models.CharField(max_length=255)

    username = models.CharField(max_length=255)

    password = models.TextField()

    def decrypt_password(self, key):
        return utils.decrypt(self.password, key)

    @staticmethod
    def encrypt_password(key, password):
        return utils.encrypt(password, key)


class User(models.Model):
    username = models.CharField(max_length=255)

    password = models.CharField(max_length=255)

    group_key = models.TextField()


    @staticmethod
    def login(username, password):
        try:
            user = User.objects.get(username=username)
        except:
            return False

        if hashers.check_password(password, user.password):
            return user
        return False
