

class ContantData:
    """
    Using this class you can access all error, success, require and field error msg.
    """
    # msg
    account_created = "Account created successfully."
    insert_calories = "Calorie value inserted successfully."
    setting_create = "Setting create successfully."
    setting_update = "Setting updated successfully."
    calorie_update = "Calorie information updated successfully."
    calorie_deleted = "Calorie information deleted successfully."
    setting_deleted = "Setting deleted successfully."
    account_deleted = "Account deleted successfully."
    user_deleted = "User deleted successfully."
    account_updated = "Account updated."
    first_name_update = "First name update successfully."
    last_name_update = "Last name update successfully."
    password_update = "Password update successfully."
    already_have_account = "Calorie setting already available."
    data_found = "Data available."
    data_not_found = "Data not available."
    user_available = "User already exists please try with different email."

    user_login = "Login Successfully."

    # error msg
    email_required = "Email required."
    email_invalid = "Invalid email."
    password_required = "Password required."
    first_name_required = "First name required."
    last_name_required = "Last name required."
    role_required = "User role required."
    user_type_required = "User type required."
    calorie_required = "Calorie required."
    calorie_id_required = "Calorie id required."
    meal_required = "Meals required."
    calorie_note_required = "Calorie note required."
    calorie_not_available = "Calorie not available."
    calorie_item_id = "Calorie item id required."
    calorie_meal_or_text = "Calorie, text or meals field required to update."
    empty_setting_to_update = "No setting available to update."
    empty_calorie_to_delete = "No calorie available to delete."
    empty_setting_to_delete = "No setting available to delete."
    password_length = "Password length must be grater than 8 Character."
    first_name_length = "First name length must be greater than 2 Character."
    last_name_length = "Last name length must be greater than 2 Character."
    account_create_by_field_error = "Please provide account, creating user type."
    all_and_self_regular = "Please provide self_user or all_regular_users key."
    specific_regular_user_field_error = "Please provide self_user or all_regular_users key."
    self_regular_manager_user_field_error = "Please provide self_user, all_manager_user or all_regular_user key."
    self_all_regular_all_manager_and_all_admin_user_field_error = "Please provide self_user, all_manager_user, all_regular_user" \
                                            " or all_admin_user key."
    specific_regular_manager_admin_user_field_error = "Please provide specific_regular_users, specific_manager_users or " \
                                                "specific_admin_users key."
    specific_regular_manager_user_field_error = "Please provide specific_regular_users, specific_manager_users."
    first_last_name_and_password_field_error = "First Name, Last Name or Password field required to update."
    invalid_user = "Invalid user."

    unAuthorizedUser = "UnAuthorized user."
    email_pwd_invalid = "Email and password invalid."

    """ account creating user type """
    create_acc_by_regular_user = "regular"
    create_acc_by_manager_user = "manager"
    create_acc_by_admin_user = "admin"
    can_not_create_account = 2
    can_not_create_account_txt = "Can not create account please check role and created by user field."

    all_regular_user_key = "all_regular_users"
    all_manager_user_key = "all_manager_users"
    all_admin_user_key = "all_admin_users"

    specific_regular_user_key = "specific_regular_user"
    specific_manager_user_key = "specific_manager_user"
    specific_admin_user_key = "specific_admin_user"


