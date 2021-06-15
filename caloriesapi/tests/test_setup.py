from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.authtoken.models import Token as A_Token
from rest_framework.test import APITestCase

# Create your tests here.
from caloriesapi.models import UsersRole, UsersProfile


class TestSetUp(APITestCase):
    def setUp(self):
        self.register_url = reverse("register")
        self.login_url = reverse("login")
        self.user_setting_url = reverse("user_setting")
        self.calorie_url = reverse("calorie")
        self.get_calorie_url = reverse("get_calorie")
        self.user_info_url = reverse("user_info")
        self.get_user_info_url = reverse("get_user_info")

        # role type
        self.roleType_regular = "regular"
        self.roleType_manager = "manager"
        self.roleType_admin = "admin"

        self.user_data_one = {
            "first_name": "ganesh",
            "last_name": "singh",
            "email": "ganesh@gmail.com",
            "username": "ganesh@gmail.com",
            "password": "ganeshsingh"
        }

        self.user_data_two = {
            "first_name": "ram",
            "last_name": "singh",
            "email": "ram@gmail.com",
            "username": "ram@gmail.com",
            "password": "ramsingh"
        }

        self.user_data_three = {
            "first_name": "vox",
            "last_name": "singh",
            "email": "vox@gmail.com",
            "username": "vox@gmail.com",
            "password": "voxsingh"
        }

        self.calorie_data = {
            "number_of_calorie": 500.67
        }

        # calorie api data
        self.calorie_create_data = {
            "number_of_calorie": 500.67,
            "meals": "daal",
            "calorie_text": "eat before gym"
        }

        self.calorie_update_data = {
            "calorie_id": 1,
            "number_of_calorie": 900.00,
            "meals": "baati",
            "calorie_text": "eat after gym"
        }

        self.calorie_delete_data = {
            "calorie_id": 1
        }

        # delete user info
        self.delete_user_info_data = {
            "user_type": "admin",
            "user_id":10
        }

        # update user info
        self.update_user_info_data = {
            "user_type": "admin",
            "user_id":11,
            "first_name": "manish",
            "last_name": "sharma"
        }

        self.roleObj_regular = UsersRole.objects.create(role_type=self.roleType_regular)
        self.roleObj_manager = UsersRole.objects.create(role_type=self.roleType_manager)
        self.roleObj_admin = UsersRole.objects.create(role_type=self.roleType_admin)
        print("role created.")

        self.user_obj_one = User.objects.create(**self.user_data_one)
        self.user_obj_two = User.objects.create(**self.user_data_two)
        self.user_obj_three = User.objects.create(**self.user_data_three)
        print("user created.")

        self.userProObjOne = UsersProfile.objects.create(role_type=self.roleObj_regular, user=self.user_obj_one)
        self.userProObjTwo = UsersProfile.objects.create(role_type=self.roleObj_manager, user=self.user_obj_two)
        self.userProObjThree = UsersProfile.objects.create(role_type=self.roleObj_admin, user=self.user_obj_three)
        print("User profiles created.")

        self.userObj = User.objects.get(username=self.user_obj_one.email)
        print("User profiles created.")

        self.A_userToken = A_Token.objects.get_or_create(user=self.userObj)
        self.token_value = self.A_userToken[0].key
        return super().setUp()

    def tearDown(self):
        return super().tearDown()
