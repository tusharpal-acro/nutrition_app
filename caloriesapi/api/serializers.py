from rest_framework import serializers
from django.contrib.auth.models import User

from caloriesapi.api.contant_data import ContantData
from caloriesapi.models import UsersProfile, UserSetting, Calorie


class CreateAccountSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(allow_null=False, allow_blank=False, max_length=100, required=True)
    last_name = serializers.CharField(allow_null=False, allow_blank=False, max_length=100, required=True)
    email = serializers.EmailField(allow_null=False, allow_blank=False, max_length=250, required=True)
    password = serializers.CharField(allow_blank=False, allow_null=False, required=True)
    account_create_by = serializers.CharField(required=False)

    class Meta:
        model = UsersProfile
        fields = 'first_name', 'last_name', 'email', 'password', 'role_type', 'account_create_by'

    def create(self, validated_data):
        print("validate data and account ", validated_data)
        username = validated_data['username'] = validated_data['email']
        role_type_data = validated_data.pop('role_type')
        account_create_by_data = validated_data.pop('account_create_by')

        if (account_create_by_data == ContantData.create_acc_by_regular_user) \
                and (str(role_type_data) == ContantData.create_acc_by_regular_user):
            """
            this code run only when account create by regular user and role type user is regular.
            Other wise got the error.
            """
            # create account.
            pass
        elif (account_create_by_data == ContantData.create_acc_by_manager_user) \
                and ((str(role_type_data) == ContantData.create_acc_by_regular_user) or
                     (str(role_type_data) == ContantData.create_acc_by_manager_user)):
            """
            this code run only when account create by manager user and role type user is regular or manager.
            Other wise got the error.
            """
            pass
        elif (account_create_by_data == ContantData.create_acc_by_admin_user) \
                and ((str(role_type_data) == ContantData.create_acc_by_regular_user) or
                     (str(role_type_data) == ContantData.create_acc_by_manager_user) or
                     (str(role_type_data) == ContantData.create_acc_by_admin_user)):
            """
            this code run only when account create by admin user and role type user is regular or manager or admin.
            Other wise got the error.
            """
            pass
        else:
            return ContantData.can_not_create_account

        # role type
        roleType = {
            "role_type": role_type_data
        }
        # check account
        user_is_exists = User.objects.filter(username=username).exists()

        if user_is_exists:
            return 0
        else:
            userObject = User.objects.create(**validated_data)
            role_type = UsersProfile.objects.create(**roleType, user=userObject)
            return userObject


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(allow_null=False, allow_blank=False, max_length=250, required=True)
    password = serializers.CharField(allow_blank=False, allow_null=False, required=True)


class UserSettingSerializer(serializers.Serializer):
    number_of_calorie = serializers.FloatField(required=False)


class CalorieSerializer(serializers.Serializer):
    calorie_id = serializers.IntegerField(required=False)
    number_of_calorie = serializers.FloatField(required=True)
    meals = serializers.CharField(required=True)
    calorie_text = serializers.CharField(required=False)


class CalorieFilterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Calorie
        fields = ['id', 'meals', 'calorie', 'calorie_note']


class UserDetailsSerializer(serializers.Serializer):
    user_type = serializers.CharField(required=False)
    user_id = serializers.IntegerField(required=False)
    """ for update first , last name or password"""
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    password = serializers.CharField(required=False)


class UserDetailsFilterSerializer(serializers.ModelSerializer):
    role_type = serializers.SerializerMethodField()

    def get_role_type(self, obj):
        try:
            userProObj = UsersProfile.objects.filter(user_id=obj.id).select_related(
                "user").values("role_type")
        except UsersProfile.DoesNotExist:
            userProObj = None

        role_type_is = ""
        if len(userProObj) != 0:
            role_type_Id = userProObj[0]['role_type']
            if role_type_Id == 1:
                role_type_is = ContantData.create_acc_by_regular_user
            elif role_type_Id == 2:
                role_type_is = ContantData.create_acc_by_manager_user
            else:
                role_type_is = ContantData.create_acc_by_admin_user

        return role_type_is


    class Meta:
        model = User
        fields = 'id', 'first_name', 'last_name', 'email', 'role_type'
