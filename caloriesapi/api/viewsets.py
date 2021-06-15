import re

from django.core.validators import RegexValidator
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.permissions import IsAuthenticated

from caloriesapi.api.serializers import CreateAccountSerializer, LoginSerializer, \
    CalorieSerializer, UserSettingSerializer, UserDetailsSerializer, CalorieFilterSerializer,\
    UserDetailsFilterSerializer
from rest_framework import status
from caloriesapi.api.contant_data import ContantData
from rest_framework.response import Response
from caloriesapi.models import UsersProfile, UserSetting, Calorie
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token


class EmailValidator(RegexValidator):

    def __call__(self, value):
        try:
            super(EmailValidator, self).__call__(value)
        except ValidationError as e:

            if value and u'@' in value:
                parts = value.split(u'@')
                try:
                    parts[-1] = parts[-1].encode('idna')
                except UnicodeError:
                    raise e
                super(EmailValidator, self).__call__(u'@'.join(parts))
            else:
                return ContantData.email_invalid


class CreateAccountViewSets(CreateAPIView):
    serializer_class = CreateAccountSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            firstName = serializer.validated_data['first_name']
            lastName = serializer.validated_data['last_name']
            account_create_by = serializer.validated_data['account_create_by']

            if len(firstName) <= 2:
                msg = ContantData.first_name_length
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg
                }
                return Response(data)
            elif len(lastName) <= 2:
                msg = ContantData.last_name_length
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg
                }
                return Response(data)
            elif account_create_by is None:
                msg = ContantData.account_create_by_field_error
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg
                }
                return Response(data)

            self.perform_create(serializer)
            user_obj = serializer.instance

            if user_obj is ContantData.can_not_create_account:
                msg = ContantData.can_not_create_account_txt
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg
                }
            elif user_obj is 0:
                msg = ContantData.user_available
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg
                }
            else:
                msg = ContantData.account_created
                data = {
                    "status_code": status.HTTP_201_CREATED,
                    "message": msg
                }

            return Response(data)
        else:
            firstName = serializer.data['first_name']
            lastName = serializer.data['last_name']
            emailName = serializer.data['email']
            password = serializer.data['password']
            role_type = serializer.data['role_type']

            msg = ""
            if firstName is "":
                msg = ContantData.first_name_required
            elif lastName is "":
                msg = ContantData.last_name_required
            elif emailName is "":
                msg = ContantData.email_required
            elif password is "":
                msg = ContantData.password_required
            elif role_type is "":
                msg = ContantData.role_required
            elif len(password) <= 8:
                msg = ContantData.password_length
            elif emailName is not "":
                email_re = re.compile(
                    r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
                    r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-011\013\014\016-\177])*"'  # quoted-string
                    r')@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?$', re.IGNORECASE)  # domain
                validate_email = EmailValidator(email_re, ContantData.email_invalid, ContantData.email_invalid)
                msg = validate_email.message

            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg
            }
            return Response(data)


def getPersonalData(request):
    try:
        userObj = User.objects.get(username=request.user)
    except User.DoesNotExist:
        userObj = None

    if userObj is not None:
        resultDict = {
            "id": userObj.id,
            "first_name": userObj.first_name,
            "last_name": userObj.last_name,
            "email": userObj.email,
        }
        return resultDict
    else:
        msg = ContantData.data_not_found
        data = {
            "status_code": status.HTTP_404_NOT_FOUND,
            "message": msg,
        }
        return data


def getDataByRoleType(roleTypeId):
    data_list = None
    data_type = None
    if roleTypeId == 1:
        data_list = []
        data_type = ContantData.all_regular_user_key
    elif roleTypeId == 2:
        data_list = []
        data_type = ContantData.all_manager_user_key
    else:
        data_list = []
        data_type = ContantData.all_admin_user_key
    # all managers user data
    try:
        userProObj = UsersProfile.objects.filter(role_type=roleTypeId).select_related(
            "user").values("role_type", "user_id")
    except UsersProfile.DoesNotExist:
        userProObj = None

    if len(userProObj) != 0:
        for uId in userProObj:
            userId = uId['user_id']
            try:
                # it will return all regular user info.
                userObj = User.objects.get(id=userId)
            except User.DoesNotExist:
                userObj = None
            if userObj is not None:
                resultDict = {
                    "id": userObj.id,
                    "first_name": userObj.first_name,
                    "last_name": userObj.last_name,
                    "email": userObj.email,
                }
                data_list.append(resultDict)
            else:
                msg = ContantData.data_not_found
                data = {
                    "status_code": status.HTTP_404_NOT_FOUND,
                    "message": msg,
                }
                return data

        data = {
            "status_code": status.HTTP_200_OK,
            "message": ContantData.data_found,
            data_type: data_list
        }
        return data
    else:
        msg = ContantData.data_not_found
        data = {
            "status_code": status.HTTP_404_NOT_FOUND,
            "message": msg,
        }
        return data


def getAllDataByRoleTypeIdAndUserId(user_id, roleTypeId):
    # get specific regular, manager, and admin users data
    data_type = None
    if roleTypeId == 1:
        data_type = ContantData.specific_regular_user_key
    elif roleTypeId == 2:
        data_type = ContantData.specific_manager_user_key
    else:
        data_type = ContantData.specific_admin_user_key

    try:
        userProObj = UsersProfile.objects.filter(user_id=user_id, role_type=roleTypeId).select_related(
            "user").values("role_type", "user_id")
    except UsersProfile.DoesNotExist:
        userProObj = None

    if len(userProObj) != 0:
        for uId in userProObj:
            userId = uId['user_id']
            try:
                userObj = User.objects.filter(id=userId).values("id", "first_name", "last_name",
                                                                "email")
            except User.DoesNotExist:
                userObj = None
            if len(userObj) != 0:
                msg = ContantData.data_found
                data = {
                    "status_code": status.HTTP_200_OK,
                    "message": msg,
                    data_type: userObj
                }
                return data
            else:
                msg = ContantData.data_not_found
                data = {
                    "status_code": status.HTTP_404_NOT_FOUND,
                    "message": msg
                }
                return data
    else:
        msg = ContantData.data_not_found
        data = {
            "status_code": status.HTTP_404_NOT_FOUND,
            "message": msg
        }
        return data


class UserViewSets(GenericAPIView):
    serializer_class = UserDetailsSerializer
    permission_classes = (IsAuthenticated,)

    def put(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user_type = serializer.validated_data.get('user_type')
            first_name = serializer.validated_data.get('first_name')
            last_name = serializer.validated_data.get('last_name')
            password = serializer.validated_data.get('password')

            user_type_id = 0

            if user_type is not None or user_type != "":
                if user_type == ContantData.create_acc_by_regular_user:
                    user_type_id = 1
                elif user_type == ContantData.create_acc_by_manager_user:
                    user_type_id = 2
                elif user_type == ContantData.create_acc_by_admin_user:
                    user_type_id = 3
            else:
                msg = ContantData.user_type_required
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)

            if first_name is None and last_name is None and password is None:
                msg = ContantData.first_last_name_and_password_field_error
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)

            if user_type_id == 1:
                # self update account
                try:
                    userObj = User.objects.get(username=request.user)
                except User.DoesNotExist:
                    userObj = None

                try:
                    userProObj = UsersProfile.objects.get(user_id=userObj.id, role_type=user_type_id)
                except UsersProfile.DoesNotExist:
                    userProObj = None

                if userProObj is None:
                    msg = ContantData.invalid_user
                    data = {
                        "status_code": status.HTTP_400_BAD_REQUEST,
                        "message": msg
                    }
                    return Response(data)
                else:
                    msg = ""
                    if first_name is not None:
                        if len(first_name) <= 2:
                            msg = ContantData.first_name_length
                            data = {
                                "status_code": status.HTTP_400_BAD_REQUEST,
                                "message": msg
                            }
                            return Response(data)
                        else:
                            msg = ContantData.first_name_update
                            userObj.first_name = first_name
                    elif last_name is not None:
                        if len(last_name) <= 2:
                            msg = ContantData.last_name_length
                            data = {
                                "status_code": status.HTTP_400_BAD_REQUEST,
                                "message": msg
                            }
                            return Response(data)
                        else:
                            msg = ContantData.last_name_update
                            userObj.last_name = last_name
                    elif password is not None:
                        if len(password) <= 8:
                            msg = ContantData.password_length
                            data = {
                                "status_code": status.HTTP_400_BAD_REQUEST,
                                "message": msg
                            }
                            return Response(data)
                        else:
                            msg = ContantData.password_update
                            userObj.password = password

                    userObj.save()
                    data = {
                        "status_code": status.HTTP_200_OK,
                        "message": msg
                    }
                    return Response(data)
            elif user_type_id == 2:
                user_id = serializer.validated_data.get('user_id')
                if user_id is not None:
                    # update regular users data
                    try:
                        userProObj = UsersProfile.objects.filter(user_id=user_id, role_type__lte=2).select_related(
                            "user").values("role_type", "user_id")
                    except UsersProfile.DoesNotExist or len(userProObj) == 0:
                        userProObj = None

                    if len(userProObj) != 0:
                        for uId in userProObj:
                            userId = uId['user_id']
                            try:
                                userObj = User.objects.get(id=userId)
                            except User.DoesNotExist:
                                userObj = None
                            msg = ""
                            if first_name is not None:
                                if len(first_name) <= 2:
                                    msg = ContantData.first_name_length
                                    data = {
                                        "status_code": status.HTTP_400_BAD_REQUEST,
                                        "message": msg
                                    }
                                    return Response(data)
                                else:
                                    userObj.first_name = first_name
                                    msg = ContantData.first_name_update
                            elif last_name is not None:
                                if len(last_name) <= 2:
                                    msg = ContantData.last_name_length
                                    data = {
                                        "status_code": status.HTTP_400_BAD_REQUEST,
                                        "message": msg,
                                    }
                                    return Response(data)
                                else:
                                    userObj.last_name = last_name
                                    msg = ContantData.last_name_update
                            elif password is not None:
                                if len(password) <= 8:
                                    msg = ContantData.password_length
                                    data = {
                                        "status_code": status.HTTP_400_BAD_REQUEST,
                                        "message": msg
                                    }
                                    return Response(data)
                                else:
                                    userObj.password = password
                                    msg = ContantData.password_update

                            userObj.save()
                            data = {
                                "status_code": status.HTTP_200_OK,
                                "message": msg
                            }
                            return Response(data)
                    else:
                        msg = ContantData.invalid_user
                        data = {
                            "status_code": status.HTTP_400_BAD_REQUEST,
                            "message": msg
                        }
                        return Response(data)
                else:
                    # update self user
                    # self update account
                    try:
                        userObj = User.objects.get(username=request.user)
                    except User.DoesNotExist:
                        userObj = None
                    try:
                        userProObj = UsersProfile.objects.get(user_id=userObj.id, role_type=user_type_id)
                    except UsersProfile.DoesNotExist:
                        userProObj = None

                    if userProObj is None:
                        msg = ContantData.invalid_user
                        data = {
                            "status_code": status.HTTP_400_BAD_REQUEST,
                            "message": msg
                        }
                        return Response(data)
                    else:
                        if first_name is not None:
                            if len(first_name) <= 2:
                                msg = ContantData.first_name_length
                                data = {
                                    "status_code": status.HTTP_400_BAD_REQUEST,
                                    "message": msg
                                }
                                return Response(data)
                            else:
                                userObj.first_name = first_name
                                msg = ContantData.first_name_update
                        elif last_name is not None:
                            msg = ""
                            if len(last_name) <= 2:
                                msg = ContantData.last_name_length
                                data = {
                                    "status_code": status.HTTP_400_BAD_REQUEST,
                                    "message": msg,
                                }
                                return Response(data)
                            else:
                                userObj.last_name = last_name
                                msg = ContantData.last_name_update
                        elif password is not None:
                            if len(password) <= 8:
                                msg = ContantData.password_length
                                data = {
                                    "status_code": status.HTTP_400_BAD_REQUEST,
                                    "message": msg,
                                }
                                return Response(data)
                            else:
                                userObj.password = password
                                msg = ContantData.password_update

                        userObj.save()
                        data = {
                            "status_code": status.HTTP_200_OK,
                            "message": msg
                        }
                        return Response(data)
            else:
                # update admin self or regular or manager user data.
                user_id = serializer.validated_data.get('user_id')
                if user_id is not None:
                    # update regular users data
                    try:
                        userProObj = UsersProfile.objects.filter(user_id=user_id, role_type__lte=3).select_related(
                            "user").values("role_type", "user_id")
                    except len(userProObj) == 0:
                        userProObj = None

                    if len(userProObj) != 0:
                        for uId in userProObj:
                            userId = uId['user_id']
                            try:
                                userObj = User.objects.get(id=userId)
                            except User.DoesNotExist:
                                userObj = None
                            msg = ""
                            if first_name is not None:
                                if len(first_name) <= 2:
                                    msg = ContantData.first_name_length
                                    data = {
                                        "status_code": status.HTTP_400_BAD_REQUEST,
                                        "message": msg
                                    }
                                    return Response(data)
                                else:
                                    userObj.first_name = first_name
                                    msg = ContantData.first_name_update
                            elif last_name is not None:
                                if len(last_name) <= 2:
                                    msg = ContantData.last_name_length
                                    data = {
                                        "status_code": status.HTTP_400_BAD_REQUEST,
                                        "message": msg
                                    }
                                    return Response(data)
                                else:
                                    userObj.last_name = last_name
                                    msg = ContantData.last_name_update
                            elif password is not None:
                                if len(password) <= 8:
                                    msg = ContantData.password_length
                                    data = {
                                        "status_code": status.HTTP_400_BAD_REQUEST,
                                        "message": msg,
                                    }
                                    return Response(data)
                                else:
                                    userObj.password = password
                                    msg = ContantData.password_update

                            userObj.save()
                            data = {
                                "status_code": status.HTTP_200_OK,
                                "message": msg
                            }
                            return Response(data)
                    else:
                        msg = ContantData.invalid_user
                        data = {
                            "status_code": status.HTTP_400_BAD_REQUEST,
                            "message": msg
                        }
                        return Response(data)
                else:
                    # update self user
                    # self update account
                    try:
                        userObj = User.objects.get(username=request.user)
                    except User.DoesNotExist:
                        userObj = None

                    try:
                        userProObj = UsersProfile.objects.get(user_id=userObj.id, role_type=user_type_id)
                    except UsersProfile.DoesNotExist:
                        userProObj = None

                    if userProObj is None:
                        msg = ContantData.invalid_user
                        data = {
                            "status_code": status.HTTP_400_BAD_REQUEST,
                            "message": msg
                        }
                        return Response(data)
                    else:
                        msg = ""
                        if first_name is not None:
                            if len(first_name) <= 2:
                                msg = ContantData.first_name_length
                                data = {
                                    "status_code": status.HTTP_400_BAD_REQUEST,
                                    "message": msg
                                }
                                return Response(data)
                            else:
                                userObj.first_name = first_name
                                msg = ContantData.first_name_update
                        elif last_name is not None:
                            if len(last_name) <= 2:
                                msg = ContantData.last_name_length
                                data = {
                                    "status_code": status.HTTP_400_BAD_REQUEST,
                                    "message": msg,
                                }
                                return Response(data)
                            else:
                                userObj.last_name = last_name
                                msg = ContantData.last_name_update
                        elif password is not None:
                            if len(password) <= 8:
                                msg = ContantData.password_length
                                data = {
                                    "status_code": status.HTTP_400_BAD_REQUEST,
                                    "message": msg,
                                }
                                return Response(data)
                            else:
                                userObj.password = password
                                msg = ContantData.password_update

                        userObj.save()
                        data = {
                            "status_code": status.HTTP_200_OK,
                            "message": msg
                        }
                        return Response(data)
        else:
            user_type = serializer.data['user_type']
            first_name = serializer.data['first_name']
            password = serializer.data['password']
            last_name = serializer.data['last_name']

            msg = ""
            if user_type is "":
                msg = ContantData.user_type_required
            elif first_name is "":
                msg = ContantData.first_name_required
            elif last_name is "":
                msg = ContantData.last_name_required
            elif password is "":
                msg = ContantData.password_required

            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg
            }
            return Response(data)
        
    def delete(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user_type = serializer.validated_data.get('user_type')
            user_id = serializer.validated_data.get('user_id')
            user_type_id = 0
            if user_type is not None or user_type != "":
                if user_type == ContantData.create_acc_by_regular_user:
                    user_type_id = 1
                elif user_type == ContantData.create_acc_by_manager_user:
                    user_type_id = 2
                elif user_type == ContantData.create_acc_by_admin_user:
                    user_type_id = 3
            else:
                msg = ContantData.user_type_required
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)

            if user_type_id == 1:
                # self update account
                try:
                    userObj = User.objects.get(username=request.user)
                except User.DoesNotExist:
                    userObj = None

                userObj.delete()
                msg = ContantData.user_deleted
                data = {
                    "status_code": status.HTTP_200_OK,
                    "message": msg
                }
                return Response(data)
            elif user_type_id == 2:
                user_id = serializer.validated_data.get('user_id')
                if user_id is not None:
                    # update regular users data
                    try:
                        userProObj = UsersProfile.objects.filter(user_id=user_id, role_type__lte=2).select_related(
                            "user").values("role_type",
                                           "user_id")
                    except UsersProfile.DoesNotExist:
                        userProObj = None

                    if len(userProObj) != 0:
                        for uId in userProObj:
                            userId = uId['user_id']
                            try:
                                userObj = User.objects.get(id=userId)
                            except User.DoesNotExist:
                                userObj = None
                            userObj.delete()
                            msg = ""
                            data = {
                                "status_code": status.HTTP_200_OK,
                                "message": msg
                            }
                            return Response(data)
                    else:
                        msg = ContantData.invalid_user
                        data = {
                            "status_code": status.HTTP_400_BAD_REQUEST,
                            "message": msg
                        }
                        return Response(data)

                else:
                    # update self user
                    # self update account
                    try:
                        userObj = User.objects.get(username=request.user)
                    except User.DoesNotExist:
                        userObj = None

                    userObj.delete()
                    msg = ContantData.user_deleted
                    data = {
                        "status_code": status.HTTP_200_OK,
                        "message": msg
                    }
                    return Response(data)
            else:
                # update admin self or regular or manager user data.
                user_id = serializer.validated_data.get('user_id')
                if user_id is not None:
                    # update regular users data
                    try:
                        userProObj = UsersProfile.objects.filter(user_id=user_id, role_type__lte=3).select_related(
                            "user").values("role_type", "user_id")
                    except UsersProfile.DoesNotExist:
                        userProObj = None

                    if len(userProObj) != 0:
                        for uId in userProObj:
                            userId = uId['user_id']
                            try:
                                userObj = User.objects.get(id=userId)
                            except User.DoesNotExist:
                                userObj = None
                            userObj.delete()
                            msg = ContantData.user_deleted
                            data = {
                                "status_code": status.HTTP_200_OK,
                                "message": msg
                            }
                            return Response(data)
                    else:
                        msg = ContantData.invalid_user
                        data = {
                            "status_code": status.HTTP_200_OK,
                            "message": msg
                        }
                        return Response(data)
                else:
                    # update self user
                    # self update account
                    try:
                        userObj = User.objects.get(username=request.user)
                    except User.DoesNotExist:
                        userObj = None

                    userObj.delete()
                    msg = ContantData.user_deleted
                    data = {
                        "status_code": status.HTTP_200_OK,
                        "message": msg
                    }
                    return Response(data)


class LoginAccountViewSets(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            password = serializer.validated_data.get('password')
            email = serializer.validated_data.get('email')

            if email is "":
                msg = ContantData.email_required
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg
                }
                return Response(data)
            elif password is "":
                msg = ContantData.password_required
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg
                }
                return Response(data)
            else:
                try:
                    userObj = User.objects.get(username=email)
                except User.DoesNotExist:
                    msg = ContantData.email_pwd_invalid
                    data = {
                        "status_code": status.HTTP_400_BAD_REQUEST,
                        "message": msg
                    }
                    return Response(data)

                if userObj is not None:
                    userToken = Token.objects.get_or_create(user=userObj)
                    msg = ContantData.user_login
                    data = {
                        "status_code": status.HTTP_200_OK,
                        "message": msg,
                        "authentication_toke": userToken[0].key
                    }
                    return Response(data)


class UserSettingViewSets(GenericAPIView):
    serializer_class = UserSettingSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            calorie_value = serializer.validated_data.get('number_of_calorie')
            if calorie_value is "" or calorie_value is None:
                msg = ContantData.calorie_required
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)
            else:
                try:
                    userobj = User.objects.get(username=request.user)
                except User.DoesNotExist:
                    msg = ContantData.unAuthorizedUser
                    data = {
                        "status_code": status.HTTP_400_BAD_REQUEST,
                        "message": msg,
                    }
                    return Response(data)

                if userobj is not None:

                    try:
                        userSettingObj = UserSetting.objects.get(user_id=userobj.id)
                    except UserSetting.DoesNotExist:
                        userSettingObj = None

                    if userSettingObj is not None:
                        msg = ContantData.already_have_account
                        data = {
                            "status_code": status.HTTP_404_NOT_FOUND,
                            "message": ContantData.data_not_found,
                            "data": msg
                        }
                        return Response(data)
                    else:
                        newUserSettingObj = UserSetting()
                        newUserSettingObj.calorie_per_day = calorie_value
                        newUserSettingObj.user = userobj
                        newUserSettingObj.save()
                        msg = ContantData.setting_create
                        data = {
                            "status_code": status.HTTP_201_CREATED,
                            "message": msg,
                        }
                        return Response(data)
        else:
            msg = ContantData.calorie_required
            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg,
            }
            return Response(data)

    def get(self, request):
        try:
            userobj = User.objects.get(username=request.user)
        except User.DoesNotExist:
            msg = ContantData.unAuthorizedUser
            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg,
            }
            return Response(data)

        if userobj:
            try:
                userSettingObj = UserSetting.objects.filter(user_id=userobj.id).values('calorie_per_day')
            except UserSetting.DoesNotExist or len(userSettingObj) is 0:
                msg = ContantData.data_not_found
                data = {
                    "status_code": status.HTTP_404_NOT_FOUND,
                    "message": msg,
                }
                return Response(data)

            if len(userSettingObj) is not 0:
                msg = ContantData.data_found
                data = {
                    "status_code": status.HTTP_200_OK,
                    "message": msg,
                    "Number_of_calorie": userSettingObj[0]['calorie_per_day']
                }
                return Response(data)
            else:
                msg = ContantData.unAuthorizedUser
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)
        else:
            msg = ContantData.unAuthorizedUser
            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg,
            }
            return Response(data)

    def put(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            calorie_value = serializer.validated_data.get('number_of_calorie')
            if calorie_value is "" or calorie_value is None:
                msg = ContantData.calorie_required
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg
                }
                return Response(data)
            else:
                try:
                    userobj = User.objects.get(username=request.user)
                except User.DoesNotExist:
                    msg = ContantData.unAuthorizedUser
                    data = {
                        "status_code": status.HTTP_400_BAD_REQUEST,
                        "message": msg,
                    }
                    return Response(data)

                if userobj:
                    try:
                        userSettingObj = UserSetting.objects.get(user_id=userobj.id)
                    except UserSetting.DoesNotExist:
                        userSettingObj = None

                    if userSettingObj is not None:
                        userSettingObj.calorie_per_day = calorie_value
                        userSettingObj.save()
                        msg = ContantData.setting_update
                        data = {
                            "status_code": status.HTTP_200_OK,
                            "message": msg,
                        }
                        return Response(data)
                    else:
                        msg = ContantData.empty_setting_to_update
                        data = {
                            "status_code": status.HTTP_400_BAD_REQUEST,
                            "message": msg,
                        }
                        return Response(data)
        else:
            msg = ContantData.calorie_required
            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg
            }
            return Response(data)

    def delete(self, request):
        try:
            userobj = User.objects.get(username=request.user)
        except User.DoesNotExist:
            msg = ContantData.unAuthorizedUser
            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg,
            }
            return Response(data)

        if userobj:
            try:
                userSettingObj = UserSetting.objects.get(user_id=userobj.id)
            except UserSetting.DoesNotExist:
                userSettingObj = None

            if userSettingObj is not None:
                userSettingObj.delete()
                msg = ContantData.setting_deleted
                data = {
                    "status_code": status.HTTP_200_OK,
                    "message": msg,
                }
                return Response(data)
            else:
                msg = ContantData.empty_setting_to_delete
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)


class CalorieViewSets(GenericAPIView):
    serializer_class = CalorieSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            calorie_value = serializer.validated_data.get('number_of_calorie')
            meals_value = serializer.validated_data.get('meals')
            calorie_text_value = serializer.validated_data.get('calorie_text')

            if calorie_value is "" or calorie_value is None:
                msg = ContantData.calorie_required
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)
            elif meals_value is "" or meals_value is None:
                msg = ContantData.meal_required
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)
            elif calorie_text_value is "" or calorie_text_value is None:
                msg = ContantData.calorie_note_required
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)
            else:
                try:
                    userobj = User.objects.get(username=request.user)
                except User.DoesNotExist:
                    msg = ContantData.unAuthorizedUser
                    data = {
                        "status_code": status.HTTP_400_BAD_REQUEST,
                        "message": msg,
                    }
                    return Response(data)

                if userobj is not None:
                    try:
                        userProObj = UsersProfile.objects.get(user_id=userobj.id)
                    except UsersProfile.DoesNotExist:
                        msg = ContantData.data_not_found
                        data = {
                            "status_code": status.HTTP_404_NOT_FOUND,
                            "message": msg,
                        }
                        return Response(data)

                    if userProObj is not None:
                        # check calorie value is less then from setting calorie value or not.
                        try:
                            userSettingObj = UserSetting.objects.get(user_id=request.user.id)
                        except UserSetting.DoesNotExist:
                            userSettingObj = None

                        if userSettingObj is not None:
                            if userSettingObj.calorie_per_day < calorie_value:
                                caloriePerDay = True
                            else:
                                caloriePerDay = False
                        else:
                            caloriePerDay = False

                        calorieObj = Calorie()
                        calorieObj.meals = meals_value
                        calorieObj.calorie_note = calorie_text_value
                        calorieObj.calorie = calorie_value
                        calorieObj.userprofile = userProObj
                        calorieObj.calorie_per_day = caloriePerDay
                        calorieObj.save()

                        msg = ContantData.insert_calories
                        data = {
                            "status_code": status.HTTP_201_CREATED,
                            "message": msg,
                        }
                        return Response(data)
                    else:
                        msg  = ContantData.data_not_found
                        data = {
                            "status_code": status.HTTP_404_NOT_FOUND,
                            "message": msg,
                        }
                        return Response(data)
                else:
                    msg = ContantData.unAuthorizedUser
                    data = {
                        "status_code": status.HTTP_400_BAD_REQUEST,
                        "message": msg,
                    }
                    return Response(data)
        else:
            calorie_text = serializer.data['calorie_text']
            meals = serializer.data['meals']
            number_of_calorie = serializer.data['number_of_calorie']

            msg = ""
            if calorie_text is "":
                msg = ContantData.calorie_note_required
            elif meals is "":
                msg = ContantData.meal_required
            elif number_of_calorie is "":
                msg = ContantData.calorie_required

            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg
            }
            return Response(data)

    def put(self, request):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            calorie_id_value = serializer.validated_data.get('calorie_id')
            calorie_value = serializer.validated_data.get('number_of_calorie')
            meals_value = serializer.validated_data.get('meals')
            calorie_text_value = serializer.validated_data.get('calorie_text')

            if calorie_id_value is None or calorie_id_value == " ":
                msg = ContantData.calorie_item_id
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)

            try:
                userobj = User.objects.get(username=request.user)
            except User.DoesNotExist:
                msg = ContantData.unAuthorizedUser
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)

            if userobj is not None:
                try:
                    userProObj = UsersProfile.objects.get(user_id=userobj.id)
                except UsersProfile.DoesNotExist:
                    msg = ContantData.data_not_found
                    data = {
                        "status_code": status.HTTP_404_NOT_FOUND,
                        "message": msg,
                    }
                    return Response(data)

                try:
                    calorieObj = Calorie.objects.get(userprofile_id=userProObj.id, id=calorie_id_value)
                except Calorie.DoesNotExist:
                    calorieObj = None

                if calorieObj is not None:
                    if calorie_value is None and calorie_text_value is None and meals_value is None:
                        msg = ContantData.calorie_meal_or_text
                        data = {
                            "status_code": status.HTTP_400_BAD_REQUEST,
                            "message": msg
                        }
                        return Response(data)
                    else:
                        if calorie_value is not None:
                            calorieObj.calorie = calorie_value
                        elif calorie_text_value is not None:
                            calorieObj.calorie_note = calorie_text_value
                        else:
                            calorieObj.meals = meals_value

                        calorieObj.save()
                        msg = ContantData.calorie_update
                        data = {
                            "status_code": status.HTTP_400_BAD_REQUEST,
                            "message": msg,
                        }
                        return Response(data)
                else:
                    msg = ContantData.empty_calorie_to_delete
                    data = {
                        "status_code": status.HTTP_400_BAD_REQUEST,
                        "message": msg,
                    }
                    return Response(data)
        else:
            calorie_id = serializer.data['calorie_id']
            calorie_text = serializer.data['calorie_text']
            meals = serializer.data['meals']
            number_of_calorie = serializer.data['number_of_calorie']

            msg = ""
            if calorie_text is "":
                msg = ContantData.calorie_note_required
            elif calorie_id is "":
                msg = ContantData.calorie_id_required
            elif meals is "":
                msg = ContantData.meal_required
            elif number_of_calorie is "":
                msg = ContantData.calorie_required

            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg
            }
            return Response(data)

    def delete(self, request):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            calorie_id_value = serializer.validated_data.get('calorie_id')

            if calorie_id_value is None or calorie_id_value == "":
                msg = ContantData.calorie_item_id
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)

            try:
                userobj = User.objects.get(username=request.user)
            except User.DoesNotExist:
                msg = ContantData.unAuthorizedUser
                data = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": msg,
                }
                return Response(data)

            if userobj is not None:
                try:
                    userProObj = UsersProfile.objects.get(user_id=userobj.id)
                except UsersProfile.DoesNotExist:
                    msg = ContantData.data_not_found
                    data = {
                        "status_code": status.HTTP_404_NOT_FOUND,
                        "message": msg,
                    }
                    return Response(data)

                try:
                    calorieObj = Calorie.objects.get(userprofile_id=userProObj.id, id=calorie_id_value)
                except Calorie.DoesNotExist:
                    calorieObj = None

                if calorieObj:
                    calorieObj.delete()
                    msg = ContantData.calorie_deleted
                    data = {
                        "status_code": status.HTTP_200_OK,
                        "message": msg,
                    }
                    return Response(data)
                else:
                    msg = ContantData.data_not_found
                    data = {
                        "status_code": status.HTTP_404_NOT_FOUND,
                        "message": msg,
                    }
                    return Response(data)
        else:
            calorie_id = serializer.data['calorie_id']
            msg = ""
            if calorie_id is "" or calorie_id is None:
                msg = ContantData.calorie_item_id
            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg
            }
            return Response(data)


class GetCalorieDataFiltersViewSets(GenericAPIView):
    """
     with the help of this method you can get the all calorie data with pagination and also apply the filters.
     filters is Calorie and meals.
    """
    serializer_class = CalorieFilterSerializer
    permission_classes = (IsAuthenticated,)

    filterset_fields = ['calorie', 'meals',]

    def get(self, request):

        try:
            userobj = User.objects.get(username=request.user)
        except User.DoesNotExist:
            msg = ContantData.unAuthorizedUser
            data = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": msg,
            }
            return Response(data)

        if userobj is not None:
            try:
                userProObj = UsersProfile.objects.get(user_id=userobj.id)
            except UsersProfile.DoesNotExist:
                msg = ContantData.data_not_found
                data = {
                    "status_code": status.HTTP_404_NOT_FOUND,
                    "message": msg,
                }
                return Response(data)
        try:
            calorieObj = Calorie.objects.filter(userprofile_id=userProObj.id).values("id", "calorie", "meals",
                                                                                     "calorie_note")
        except Calorie.DoesNotExist or len(calorieObj) is 0:
            calorieObj = None

        if calorieObj is not None or len(calorieObj) != 0:
            qs = self.filter_queryset(calorieObj)
            page = self.paginate_queryset(qs)
            if page:
                serializer_obj = self.get_serializer(instance=page, many=True)
                return self.get_paginated_response({'res': "success", 'msg': serializer_obj.data})
            else:
                msg = ContantData.data_not_found
                data = {
                    "status_code": status.HTTP_404_NOT_FOUND,
                    "message": msg,
                }
                return Response(data)

        else:
            msg = ContantData.calorie_not_available
            data = {
                "status_code": status.HTTP_404_NOT_FOUND,
                "message": msg,
            }
            return Response(data)


def get_custom_paginated_response(self, querySetObj):
    """ return the data according to page. """
    qs = self.filter_queryset(querySetObj)
    page = self.paginate_queryset(qs)
    if page:
        serializer_obj = self.get_serializer(instance=page, many=True)
        return serializer_obj


class GetAllUsersInfoFiltersViewSets(GenericAPIView):
    """
        with the help of this method you can get all Users information (id, first name, last name, email and role type.)
        with pagination.
        you can also apply the filters like id, first and last name, email and role type.
        Note - if you give wrong query string or header value, then all user info data also will show.(means always data show.)
    """
    serializer_class = UserDetailsFilterSerializer
    permission_classes = (IsAuthenticated,)

    filterset_fields = ['id', 'first_name', 'last_name', 'email']

    def get(self, request):
        role_type_param = request.GET.get('role_type', None)
        role_type_id = 0
        if role_type_param:
            """ role type filter """
            if role_type_param == ContantData.create_acc_by_regular_user:
                # when regular role type user.
                role_type_id = 1
            elif role_type_param == ContantData.create_acc_by_manager_user:
                # when manager role type user.
                role_type_id = 2
            else:
                # when admin role type user.
                role_type_id = 3

            try:
                userProObj = UsersProfile.objects.filter(role_type=role_type_id).select_related(
                    "user").values("role_type", "user_id")
            except UsersProfile.DoesNotExist:
                userProObj = None

            if len(userProObj) != 0:
                id_list = []
                for uId in userProObj:
                    userId = uId['user_id']
                    id_list.append(userId)

                try:
                    # it will return all regular user info.
                    userObj = User.objects.filter(id__in=id_list)
                except User.DoesNotExist:
                    userObj = None

                paginatedSerializerResObj = get_custom_paginated_response(self, userObj)
                return self.get_paginated_response({'res': "success", 'msg': paginatedSerializerResObj.data})
            else:
                msg = ContantData.data_not_found
                data = {
                    "status_code": status.HTTP_404_NOT_FOUND,
                    "message": msg,
                }
                return Response(data)

        else:
            """ id, first name, last name and email filter """
            user_queryset = User.objects.all()
            paginatedSerializerResObj = get_custom_paginated_response(self, user_queryset)
            return self.get_paginated_response({'res': "success", 'msg': paginatedSerializerResObj.data})
