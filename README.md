# Nutrition App

A django REST API app to manage user data.

Assuming you have **python3**, **pip3** and **postgreSQL** installed in the system.

1. Open the project folder into pycharm which is having manage.py

2. Run below command to install all required libraries -

    - pip3 install -r requirements.txt

3. Setup PostgreSQL like below - 

        - 'NAME': 'calnutrition_db',

        - 'USER': 'nutrition',

        - 'PASSWORD': '123456',

    Please create database as name 'calnutrition_db', user as 'nutrition' and password as '123456'

    **OR**

    If you have already setup database with any different configuration then update all details in settings.py file.

4. Now run below commands to configure database tables - 
   
    ```python3 manage.py makemigrations```
    
    ```python3 manage.py migrate```
   
4. Now, run below command to start the server - 
    - python3 manage.py runserver
    
The server is running now, and you will get the URL in terminal, like below -

http://localhost:8000/

PLEASE FIND API DOCUMENT NAMED 'api doc.odt' IN THE SAME PROJECT FOLDER.

YOU WILL FIND ALL THE API ENDPOINTS IN THE DOCUMENT. 

