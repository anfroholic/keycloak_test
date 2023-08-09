from typing import List, Optional

import uvicorn
from fastapi import FastAPI, Depends, Query, Body, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import SecretStr

from fastapi_keycloak import FastAPIKeycloak, OIDCUser, UsernamePassword, HTTPMethod, KeycloakUser, KeycloakGroup

from pprint import pprint

test_data = {"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOdnhzMjJ0MGtCcFpEaVFDV1dIUzB2WV9qRzRZeDBINTlfSmFFLUFBVEdBIn0.eyJleHAiOjE2OTEwOTg4NDEsImlhdCI6MTY5MTA5ODU0MSwiYXV0aF90aW1lIjoxNjkxMDk3NTU1LCJqdGkiOiJhMzRiZjcyZS01NzdjLTRkZWItYjNhMi02NGVkOWQ2YWVhODgiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODUvYXV0aC9yZWFsbXMvVGVzdCIsInN1YiI6ImY3ZWVlNWYxLTQ4YjYtNGI1MC1hNWRiLTk2NmJiYjdlZDZmMiIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjliNWQwNzdiLTg5YWUtNDY0Ny05ODVjLTM2OGRjYmVjZWNkNyIsImFjciI6IjAiLCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiI5YjVkMDc3Yi04OWFlLTQ2NDctOTg1Yy0zNjhkY2JlY2VjZDciLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJhbmZybzIgYW5mcm8yIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYkBhLmNvbSIsImdpdmVuX25hbWUiOiJhbmZybzIiLCJmYW1pbHlfbmFtZSI6ImFuZnJvMiIsImVtYWlsIjoiYkBhLmNvbSJ9.ZoOxhrWUi1vYlB8ynR8E29hLziHgmsKAVJgU9DomytzShIDYQPi-goJ8d5A_fSbj_4956-NAFwBtf8xcC9kOBv3sUJ-qKazspIihzZBuo-tiNS8JmTYEJb8Vkag1yS7drdW4kbkBu0XNOYMHgVDnXfGCu8HKPttf-QIAolryfVHFYwO2dO-LhDahhRk2a1l2NnUIGcx2GX4yTCjLGxyyB7uPSWsYgYFvDwyhIkISt68BIFWxOZsouKwOumBhmHzWbhYQnPnFVaz8MlfKt7GN56AgOVPo2cAn1X9ZhlJxLZxfBrXOnSvyCZ2aly5gcjelCdUOPH_59VsnktERSCdsrg","refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmNjg3N2RhOS0wZDQwLTQ1ZWItOTljYi1mZGQ3YTFmMTdmNTUifQ.eyJleHAiOjE2OTExMDAzNDEsImlhdCI6MTY5MTA5ODU0MSwianRpIjoiMGE1N2QzYWItYjQ2YS00NWQ3LWIxYjMtNTQxMTdmOGY1YzE5IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDg1L2F1dGgvcmVhbG1zL1Rlc3QiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODUvYXV0aC9yZWFsbXMvVGVzdCIsInN1YiI6ImY3ZWVlNWYxLTQ4YjYtNGI1MC1hNWRiLTk2NmJiYjdlZDZmMiIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ0ZXN0LWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiI5YjVkMDc3Yi04OWFlLTQ2NDctOTg1Yy0zNjhkY2JlY2VjZDciLCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiI5YjVkMDc3Yi04OWFlLTQ2NDctOTg1Yy0zNjhkY2JlY2VjZDcifQ.oZQ-eB-ekQuJt9i-dk1_4RryKZfEHgfKkOsulbGm4Hk"}
# pprint(test_data)
app = FastAPI()
idp = FastAPIKeycloak(
    server_url="http://host.docker.internal:8085/auth",
    client_id="test-client",
    client_secret="GzgACcJzhzQ4j8kWhmhazt7WSdxDVUyE",
    admin_client_secret="BIcczGsZ6I8W5zf0rZg5qSexlloQLPKB",
    realm="Test",
    callback_uri="http://localhost:8081/callback"
)
idp.add_swagger_config(app)


# Admin
@app.get("/", response_class=HTMLResponse)
def home():
    return """
Here is some stuff <br>
<a href="http://localhost:8085/auth/realms/Test/protocol/openid-connect/auth?response_type=code&client_id=test-client&redirect_uri=http://localhost:8081/callback">link</a><br>

<a href="http://localhost:8081/identity-providers">http://localhost:8081/identity-providers</a><br>
<a href="http://localhost:8081/idp-configuration">http://localhost:8081/idp-configuration</a><br>
<a href="http://localhost:8081/idp-configuration">http://localhost:8081/idp-configuration</a><br>
"""

@app.post("/proxy", tags=["admin-cli"])
def proxy_admin_request(relative_path: str, method: HTTPMethod, additional_headers: dict = Body(None), payload: dict = Body(None)):
    return idp.proxy(
        additional_headers=additional_headers,
        relative_path=relative_path,
        method=method,
        payload=payload
    )


@app.get("/identity-providers", tags=["admin-cli"])
def get_identity_providers():
    return idp.get_identity_providers()


@app.get("/idp-configuration", tags=["admin-cli"])
def get_idp_config():
    open_id_config = idp.open_id_configuration
    print(open_id_config)
    return idp.open_id_configuration


# User Management

@app.get("/users", tags=["user-management"])
def get_users():
    users = idp.get_all_users() 
    print(users)
    return 'something' 
    #  return users


@app.get("/user", tags=["user-management"])
def get_user_by_query(query: str = None):
    print('this is the query', query)
    return idp.get_user(query=query)


@app.post("/users", tags=["user-management"])
def create_user(first_name: str, last_name: str, email: str, password: SecretStr, id: str = None):
    return idp.create_user(first_name=first_name, last_name=last_name, username=email, email=email, password=password.get_secret_value(), id=id)


@app.get("/user/{user_id}", tags=["user-management"])
def get_user(user_id: str = None):
    print('this is the user_id', user_id)
    user = idp.get_user(user_id=user_id)
    return user


@app.put("/user", tags=["user-management"])
def update_user(user: KeycloakUser):
    return idp.update_user(user=user)


@app.delete("/user/{user_id}", tags=["user-management"])
def delete_user(user_id: str):
    return idp.delete_user(user_id=user_id)


@app.put("/user/{user_id}/change-password", tags=["user-management"])
def change_password(user_id: str, new_password: SecretStr):
    return idp.change_password(user_id=user_id, new_password=new_password)


@app.put("/user/{user_id}/send-email-verification", tags=["user-management"])
def send_email_verification(user_id: str):
    return idp.send_email_verification(user_id=user_id)


# Role Management

@app.get("/roles", tags=["role-management"])
def get_all_roles():
    return idp.get_all_roles()


@app.get("/role/{role_name}", tags=["role-management"])
def get_role(role_name: str):
    return idp.get_roles([role_name])


# Works!
@app.post("/roles", tags=["role-management"])
def add_role(role_name: str):
    print(role_name)
    return idp.create_role(role_name=role_name)

# Works!~
@app.delete("/roles", tags=["role-management"])
def delete_roles(role_name: str):
    return idp.delete_role(role_name=role_name)


# Group Management

@app.get("/groups", tags=["group-management"])
def get_all_groups():
    return idp.get_all_groups()


@app.get("/group/{group_name}", tags=["group-management"])
def get_group(group_name: str):
    return idp.get_groups([group_name])


@app.get("/group-by-path/{path: path}", tags=["group-management"])
def get_group_by_path(path: str):
    return idp.get_group_by_path(path)


@app.post("/groups", tags=["group-management"])
def add_group(group_name: str, parent_id: Optional[str] = None):
    return idp.create_group(group_name=group_name, parent=parent_id)


@app.delete("/groups", tags=["group-management"])
def delete_groups(group_id: str):
    return idp.delete_group(group_id=group_id)


# User Roles

@app.post("/users/{user_id}/roles", tags=["user-roles"])
def add_roles_to_user(user_id: str, roles: Optional[List[str]] = Query(None)):
    return idp.add_user_roles(user_id=user_id, roles=roles)


@app.get("/users/{user_id}/roles", tags=["user-roles"])
def get_user_roles(user_id: str):
    return idp.get_user_roles(user_id=user_id)


@app.delete("/users/{user_id}/roles", tags=["user-roles"])
def delete_roles_from_user(user_id: str, roles: Optional[List[str]] = Query(None)):
    return idp.remove_user_roles(user_id=user_id, roles=roles)


# User Groups

@app.post("/users/{user_id}/groups", tags=["user-groups"])
def add_group_to_user(user_id: str, group_id: str):
    return idp.add_user_group(user_id=user_id, group_id=group_id)


@app.get("/users/{user_id}/groups", tags=["user-groups"])
def get_user_groups(user_id: str):
    return idp.get_user_groups(user_id=user_id)


@app.delete("/users/{user_id}/groups", tags=["user-groups"])
def delete_groups_from_user(user_id: str, group_id: str):
    return idp.remove_user_group(user_id=user_id, group_id=group_id)


# Example User Requests

@app.get("/protected", tags=["example-user-request"])
def protected(user: OIDCUser = Depends(idp.get_current_user())):
    return user


@app.get("/current_user/roles", tags=["example-user-request"])
def get_current_users_roles(user: OIDCUser = Depends(idp.get_current_user())):
    return user.roles


@app.get("/admin", tags=["example-user-request"])
def company_admin(user: OIDCUser = Depends(idp.get_current_user(required_roles=["admin"]))):
    return f'Hi admin {user}'


@app.get("/login", tags=["example-user-request"])
def login(user: UsernamePassword = Depends()):
    return idp.user_login(username=user.username, password=user.password.get_secret_value())


# Auth Flow

@app.get("/login-link", tags=["auth-flow"])
def login_redirect():
    return '<a href="http://localhost:8085/auth/realms/Test/protocol/openid-connect/auth?response_type=code&client_id=test-client&redirect_uri=http://localhost:8081/callback">link</a>'

    # return idp.login_uri


@app.get("/callback", tags=["auth-flow"])
def callback(session_state: str, code: str):
    data = idp.exchange_authorization_code(session_state=session_state, code=code)
    if data == test_data:
        print('we have a match')
    else:
        print('no match')
    return data


@app.get("/logout", tags=["auth-flow"])
def logout():
    return idp.logout_uri

# if __name__ == '__main__':
#     uvicorn.run('key_it:app', host="127.0.0.1", port=8081)


# http://localhost:8085/auth/realms/Test/protocol/openid-connect/auth?response_type=code&client_id=test-client&redirect_uri=http://localhost:8081/callback
