def can_access(role, resource, action, is_released=False):
    if role == "Owner":
        #owner has full access
        return True

    if role == "Executor":
        #executor can update authorizations
        if resource in ["will", "logs"]:
            return True
        if resource == "authorization" and action == "write":
            return True

    if role == "Beneficiary":
        #can access will only after release condition is met
        if resource == "will" and is_released:
            return True

    return False #denied by default
