from django.db import models
from django.contrib.auth.models import User
from django.db import models


# Create your models here.
class UsersRole(models.Model):
    role_type = models.CharField(max_length=100, null=False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.role_type


class UsersProfile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False, blank=False)
    role_type = models.ForeignKey(UsersRole, on_delete=models.CASCADE, null=False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user


class Calorie(models.Model):
    userprofile = models.ForeignKey(UsersProfile, on_delete=models.CASCADE,null=False, blank=False)
    calorie = models.FloatField(null=False, blank=False)
    meals = models.CharField(max_length=200, null=False, blank=False)
    calorie_note = models.CharField(max_length=200, null=False, blank=False)
    calorie_per_day = models.BooleanField(default=False, blank=True, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.meals


class UserSetting(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,null=False, blank=False)
    calorie_per_day = models.FloatField(max_length=500, blank=False, null=False)

    def __str__(self):
        return self.calorie_per_day