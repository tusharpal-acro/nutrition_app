"""nutritioncalorie URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path


from caloriesapi.api.viewsets import CreateAccountViewSets, LoginAccountViewSets,\
    UserSettingViewSets, CalorieViewSets, UserViewSets, GetCalorieDataFiltersViewSets, GetAllUsersInfoFiltersViewSets


urlpatterns = [
    # with the help of this you can create the account of regular, manager, and admin user.
    path('nutrition/api/create_user/', CreateAccountViewSets.as_view(), name="register"),

    # with the help of the below api you can update,  delete the user.
    # you can call the put and delete method using the below URL. Only you need to change the method type.
    path('nutrition/api/user_info/', UserViewSets.as_view(), name="user_info"),

    path('nutrition/api/get_user_info/', GetAllUsersInfoFiltersViewSets.as_view(), name="get_user_info"),

    # with the help of the below api you can log in.
    path('nutrition/api/login/', LoginAccountViewSets.as_view(), name="login"),

    # with the help of the below API you can create, update and delete the calorie data.
    # call post, put and delete api using the below url. Only you need to change the method type.
    path('nutrition/api/calorie/', CalorieViewSets.as_view(), name="calorie"),

    # get all calorie data using pagination and filter by calorie and meal value. Default pagination page size is 10
    path('nutrition/api/get_calorie/', GetCalorieDataFiltersViewSets.as_view(), name="get_calorie"),

    # with the help of this API you can create, retrieve, update and delete the user setting.
    # call post, get, put and delete using the below URL. Only you need to change the method type.
    path('nutrition/api/user_setting/', UserSettingViewSets.as_view(), name="user_setting"),
]
