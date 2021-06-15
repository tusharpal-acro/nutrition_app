from rest_framework.utils import json
from rest_framework.test import APIClient
from .test_setup import TestSetUp
from caloriesapi.models import UsersProfile, UsersRole
from django.contrib.auth.models import User


class TestViews(TestSetUp):
    def test_create_get_put_delete_user_setting(self):
        calorie_update_data = {
            "number_of_calorie": 900.67
        }

        client = APIClient()
        # to create user setting data.
        client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_value)
        createRes = client.post(
            self.user_setting_url,
            json.dumps(self.calorie_data),
            content_type='application/json',
        )

        # to get user setting data
        getSetting = client.get(
            self.user_setting_url,
            content_type='application/json',
        )
        print("User setting data  ", getSetting.data)
        self.assertEqual(getSetting.status_code, getSetting.data['status_code'])

        # to update user setting data
        updateSetting = client.put(self.user_setting_url, json.dumps(calorie_update_data),
                                   content_type='application/json')

        print("updateSetting  data  ", updateSetting.data)
        self.assertEqual(updateSetting.status_code, updateSetting.data['status_code'])

        # to delete user setting data
        deleteSetting = client.delete(self.user_setting_url, content_type='application/json')

        print("deleteSetting  data  ", deleteSetting.data)
        self.assertEqual(deleteSetting.status_code, deleteSetting.data['status_code'])

    def test_create_user_setting_invalid_token(self):
        client = APIClient()
        # to create user setting data invalid token.
        client.credentials(HTTP_AUTHORIZATION='Token ' + "sdfasdfasdfasfdda")
        createRes = client.post(
            self.user_setting_url,
            json.dumps(self.calorie_data),
            content_type='application/json',
        )
        print("new createRes data ", createRes.data)

    def test_update_setting_without_data(self):
        # to update user setting without data
        client = APIClient()
        # to create user setting data.
        client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_value)
        new_updateSetting = client.put(self.user_setting_url,
                                       content_type='application/json')

        print("updateSetting  data  ", new_updateSetting.data)

    def test_create_get_put_delete_calorie(self):
        print("param value is ", self.calorie_create_data)
        client = APIClient()
        # to create calorie data.
        client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_value)
        createCalorieRes = client.post(
            self.calorie_url,
            json.dumps(self.calorie_create_data),
            content_type='application/json',
        )
        print("calorie create data ", createCalorieRes.data)

        # get calorie data
        getCalorieRes = client.get(
            self.get_calorie_url,
            content_type='application/json',
        )
        print("calorie get data ", getCalorieRes.data)

        # update calorie data
        putCalorieRes = client.put(
            self.calorie_url,
            json.dumps(self.calorie_update_data),
            content_type='application/json',
        )
        print("calorie update data ", putCalorieRes.data)

        # delete calorie data
        deleteCalorieRes = client.delete(
            self.calorie_url,
            json.dumps({"calorie_id": 1}),
            content_type='application/json',
        )
        print("calorie delete data ", deleteCalorieRes.data)

    def test_get_put_delete_user_info(self):

        client = APIClient()
        # to get all user data data.
        client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_value)
        getAllUserInfo = client.get(
            self.get_user_info_url,
            content_type='application/json',
        )
        print("getAllUserInfo  ", getAllUserInfo.data)

        # to update user info data
        putUserInfo = client.put(
            self.user_info_url,
            json.dumps(self.update_user_info_data),
            content_type='application/json',
        )
        print("putUserInfo data  ", putUserInfo.data)

        # to delete user info data
        deleteUserInfo = client.delete(self.user_info_url, content_type='application/json')

        print("deleteUserInfo  data  ", deleteUserInfo.data)

