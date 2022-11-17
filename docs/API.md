API
===

The API is implemented as a set of REST calls. Where applicable, default values are in **bold.**

## POST /auth2/hello
Responds with "Hello!"

| **Parameters** | **Name** | **In** | **Description** | **Required** | **Type** |
|----------------|----------|--------|-----------------|--------------|----------|
| ---            |

| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           | Hello!          |
|| 404           | Not Found            |

## GET /auth2/ping
Returns a timestamp

| **Parameters** | **Name** | **In** | **Description** | **Required** | **Type** |
|----------------|----------|--------|-----------------|--------------|----------|
| -              |  

| **Responses** | **HTTP Status Code** | **Description**             | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------------------|------------|-------------|-------------|
|| 200           | Successful           ||| `{"Timestamp": 1464949824}` |     |     |     |
|| 404           | Not Found            ||||     |     |     |     |

## POST /auth2/login
Returns a json object containing authorization information

| **Parameters** | **Name**      | **In** | **Description**                                                                                                                                                                                                                                                                                                                | **Required** | **Type**       |
|----------------|---------------|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|----------------|
|                | Authorization | header | Contains the username and password                                                                                                                                                                                                                                                                                             | yes          | string         |
|                | Content-Type* | header | Contains the body type required for MSAAD passthrough payloads                                                                                                                                                                                                                                                                 | no           | string         |
|                | client_id*    | body   | Specifies the requesting service client in the format “client_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx” when using MSAAD passthrough. The client_id supplied here should be the requesting application client id as registered in Azure. The client_id needs to be explicitly enabled in the IMQS Auth system via configuration. | no           | data-urlencode |
|                | login_type*   | body   | Specifies the login type in the format “login_type=msaad”                                                                                                                                                                                                                                                                      | no           | data-urlencode |


| **Responses** | **HTTP Status Code** | **Description**                                              | **Schema** | **Headers** | **Example** |
|---------------|----------------------|--------------------------------------------------------------|------------|-------------|-------------|
|| 200           | Successful           ||| `{"UserId":3618,"Identity":"joe@example.com","Roles":["2"]}` |     |     |     |
|| 404           | Not Found            ||||     |

\* Direct auth login in environments where msaad is enabled is discouraged since OAuth is preferred. However, for some 
service-to-service integration MSAAD “passthrough” is required which allows a login with username and password as 
configured in AD. Fields marked with * above is required should this method be used.

Curl example of MSAAD passthrough login request (sensitive data replaced with x):

```bash
curl --location --request POST 'https://qa1.assetworld.co.za/auth2/login' \
--header 'Authorization: Basic xxxxxxxxxxxxxxxxxxx' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' \
--data-urlencode 'login_type=msaad'
```

## POST /auth2/logout

Sets expiry to past date and updates cookie.

| **Parameters** | **Name** | **In** | **Description** | **Required** | **Type** |
|----------------|----------|--------|-----------------|--------------|----------|
| -              |

| **Responses** | **HTTP Status Code** | **Description**                 | **Schema** | **Headers** | **Example** |
|---------------|----------------------|---------------------------------|------------|-------------|-------------|
|| 200           | Successful           | Sets cookie expiry to past date |||
|| 404           | Not Found            ||||

## POST /auth2/login\_yellowfin (DEPRECATED)
Returns a list of all nodes of the specified type at (or below - depending on flags) the specified level

| **Parameters** | **Name** | **In** | **Description** | **Required** | **Type** |
|----------------|----------|--------|-----------------|--------------|----------|
| -              |

| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||||
|| 404           | Not Found            ||||

## GET /auth2/check
Returns a json object containing authorization information


| **Parameters** | **Name** | **In**                             | **Description** | **Required** | **Type** |
|----------------|----------|------------------------------------|-----------------|--------------|----------|
|| Authorization  | header   | Contains the username and password | yes             | string       |

| **Responses** | **HTTP Status Code** | **Description**                                            | **Schema** | **Headers** | **Example** |
|---------------|----------------------|------------------------------------------------------------|------------|-------------|-------------|
|| 200           | Successful           ||| {"UserId":3618,"Identity":"joe@example.com","Roles":["2"]} |
|| 400           | Bad Request          ||||
|| 401           | Unauthorized         ||||
|| 404           | Not Found            ||||


## PUT /auth2/create\_user

| **Parameters**  | **Name** | **In**                                                                              | **Description** | **Required** | **Type** |
|-----------------|----------|-------------------------------------------------------------------------------------|-----------------|--------------|----------|
|| email           | query    | The email of the user you creating. email or username required, both are not        | yes\*           | string       |
|| username        | query    | The username of the user you are creating. email or username required, both are not | yes\*           | string       |
|| firstname       | query    | The first name of the user you are creating                                         | no              | string       |
|| lastname        | query    | The last name of the user you are creating                                          | no              | string       |
|| mobilenumber    | query    | The mobile number of the user you are creating                                      | no              | string       |
|| telephonenumber | query    | The telephone number of the user you are creating                                   | no              | string       |
|| remarks         | query    | Any remarks required                                                                | no              | string       |
|| password        | query    | The password of the user you are creating                                           | no              | string       |
\* either email or username must be specified so that an identity can be created

| **Responses** | **HTTP Status Code** | **Description**                                                                                         | **Schema** | **Headers** | **Example** |
|---------------|----------------------|---------------------------------------------------------------------------------------------------------|------------|-------------|-------------|
|| 200           | Successful           ||||
|| 400           | Bad Request          ||||
|| 401           | Unauthorized         ||||
|| 403           | Forbidden            ||| <p>/auth2/create\_user => "Identity may not be empty"</p><p></p><p>"Identity already exists"</p><p></p> |
|| 404           | Not Found            ||||


## POST /auth2/update\_user

| **Parameters** | **Name** | **In**                                                                              | **Description** | **Required** | **Type** |
|----------------|----------|-------------------------------------------------------------------------------------|-----------------|--------------|----------|
|| email          | query    | The email of the user you creating. email or username required, both are not        | yes             | string       |
|| username       | query    | The username of the user you are creating. email or username required, both are not | yes             | string       |
|| firstname      | query    | The first name of the user you are creating                                         | yes             | string       |
|| lastname       | query    | The last name of the user you are creating                                          | yes             | string       |
|| mobilenumber   | query    | The mobile number of the user you are creating                                      | no              | string       |
|| authusertype   | query    | The auth user type of the user account, be it IMQS, LDAP etc                        | yes             | int          |


| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||||
|| 400           | Bad Request          ||||
|| 403           | Forbidden            ||||
|| 404           | Not Found            ||||

## POST /auth2/archive\_user

| **Parameters** | **Name** | **In**                                   | **Description** | **Required** | **Type** |
|----------------|----------|------------------------------------------|-----------------|--------------|----------|
|| userid         | query    | The userid of the user you are archiving | yes             | integer      |


| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||||
|| 400           | Bad Request          ||||
|| 403           | Forbidden            ||||
|| 404           | Not Found            ||||

## PUT /auth2/create\_group

| **Parameters** | **Name** | **In**                | **Description** | **Required** | **Type** |
|----------------|----------|-----------------------|-----------------|--------------|----------|
|| groupname      | query    | The name of the group | yes             | string       |


| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||||
|| 400           | Bad Request          ||||
|| 403           | Forbidden            ||||
|| 404           | Not Found            ||||

## POST /auth2/rename\_user

| **Parameters** | **Name** | **In**           | **Description** | **Required** | **Type** |
|----------------|----------|------------------|-----------------|--------------|----------|
|| old            | query    | The old username | yes             | string       |
|| new            | query    | The new username | yes             | string       |


| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||||
|| 400           | Bad Request          ||||
|| 403           | Forbidden            ||||
|| 404           | Not Found            ||||

## PUT /auth2/set\_group\_roles

| **Parameters** | **Name** | **In**                                        | **Description** | **Required** | **Type** |
|----------------|----------|-----------------------------------------------|-----------------|--------------|----------|
|| groupname      | query    | The name of the group we want to set roles to | yes             | string       |
|| roles          | query    | The roles we want to assign to a group        | no              | string       |


| **Responses** | **HTTP Status Code** | **Description**                                                                   | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------------------------------------------------------------------------|------------|-------------|-------------|
|| 200           | Successful           ||| /auth2/set\_group\_roles?groupname="test"&roles=500,501                           |
|| 400           | Bad Request          ||||
|| 406           | Not Acceptable       ||||
|| 404           | Not Found            ||| <p>/auth2/set\_group\_roles</p><p>"Group '' not found: Group does not exist:"</p> |

## POST /auth2/set\_user\_groups

| **Parameters** | **Name** | **In**                                          | **Description** | **Required** | **Type** |
|----------------|----------|-------------------------------------------------|-----------------|--------------|----------|
|| userid         | query    | The userid of the user we want to set groups to | yes             | integer      |     |
|| groups         | query    | List of groups we want to give to the user      | yes             | string       |     |

| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||||     |     |     |     |
|| 400           | Bad Request          ||||     |     |     |     |
|| 403           | Forbidden            ||||     |     |     |     |
|| 404           | Not Found            ||||     |     |     |     |

## POST /auth2/set\_password

| **Parameters** | **Name** | **In**                                                | **Description** | **Required** | **Type** |
|----------------|----------|-------------------------------------------------------|-----------------|--------------|----------|
|| userid         | query    | The userid of the user we want to set the password to | yes             | integer      |     |
|| password       | query    | The new password                                      | yes             | string       |     |

| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||||     |     |     |     |
|| 400           | Bad Request          ||||     |     |     |     |
|| 403           | Forbidden            ||||     |     |     |     |
|| 404           | Not Found            ||||     |     |     |     |

## POST /auth2/reset\_password\_start

| **Parameters** | **Name** | **In**                                                   | **Description** | **Required** | **Type** |
|----------------|----------|----------------------------------------------------------|-----------------|--------------|----------|
|| identity       | query    | The identity of the user who's password we want to reset | yes             | string       |     |

| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||||     |     |     |     |
|| 400           | Bad Request          ||||     |     |     |     |
|| 404           | Not Found            ||||     |     |     |     |

## POST /auth2/reset\_password\_finish

| **Parameters** | **Name** | **In**                                                 | **Description** | **Required** | **Type** |
|----------------|----------|--------------------------------------------------------|-----------------|--------------|----------|
|| userid         | query    | The userid of the user who's password we want to reset | yes             | integer      |     |
|| X-NewPassword  | header   | The new password                                       | yes             | string       |     |
|| X-ResetToken   | header   | The password token                                     | yes             | string       |     |

| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||||     |     |     |     |
|| 400           | Bad Request          ||||     |     |     |     |
|| 404           | Not Found            ||||     |     |     |     |

## GET /auth2/users
Returns a list of users just containing the users' identity and authorization, i.e. groups they belong to

| **Parameters** | **Name** | **In** | **Description** | **Required** | **Type** |
|----------------|----------|--------|-----------------|--------------|----------|
| -              |


| **Responses** | **HTTP Status Code**  | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                   | **Schema** | **Headers** | **Example** |
|---------------|-----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|-------------|-------------|
|| 200           | Successful            ||| <p>[</p><p>`  `{</p><p>`    `"Email":"",</p><p>`    `"UserName":"demo",</p><p>`    `"Groups":["enabled","admin"]</p><p>`  `},</p><p>`  `{</p><p>`    `"Email":"imqs@imqs.co.za",</p><p>`    `"UserName":"imqs",</p><p>`    `"Groups":["asset all","enabled","admin"]</p><p>`  `},</p><p>`  `{</p><p>`    `"Email":"wipuser@imqs.co.za",</p><p>`    `"UserName":"wipadmin",</p><p>`    `"Groups":["asset all","wipview","enabled","admin"]</p><p>`  `}</p><p>]</p> |     |     |     |
|| 500           | Internal Server Error ||||     |     |     |     |
|| 404           | Not Found             ||||     |     |     |     |

## GET /auth2/userobjects
Returns a list of user objects containing all the user's data and authorization.

| **Parameters** | **Name** | **In** | **Description** | **Required** | **Type** |
|----------------|----------|--------|-----------------|--------------|----------|
| -              |


| **Responses** | **HTTP Status Code**  | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | **Schema** | **Headers** | **Example** |
|---------------|-----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|-------------|-------------|
|| 200           | Successful            ||| <p>[{</p><p>` `"UserId": 3550,</p><p>` `"Email": "user1@gmail.com",</p><p>` `"Username": "user1",</p><p>` `"Name": "User1",</p><p>` `"Surname": "User1",</p><p>` `"Mobile": "",</p><p>` `"Telephone": "",</p><p>` `"Remarks": "",</p><p>` `"Created": "2019-06-12T15:08:09.4552Z",</p><p>` `"CreatedBy": " ",</p><p>` `"Modified": "2019-06-12T15:08:46.764303Z",</p><p>` `"ModifiedBy": " ",</p><p>` `"Groups": ["enabled"],</p><p>` `"AuthUserType": 0,</p><p>` `"Archived": false</p><p>` `},</p><p>` `{</p><p>` `"UserId": 3641,</p><p>` `"Email": "user2@gmail.com",</p><p>` `"Username": "user2",</p><p>` `"Name": "User2",</p><p>` `"Surname": "User2",</p><p>` `"Mobile": "",</p><p>` `"Telephone": "",</p><p>` `"Remarks": "",</p><p>` `"Created": "2019-06-14T09:33:37.935232Z",</p><p>` `"CreatedBy": "Administrator",</p><p>` `"Modified": "2019-06-20T07:18:42.593896Z",</p><p>` `"ModifiedBy": "w a",</p><p>` `"Groups": ["enabled", "admin"],</p><p>` `"AuthUserType": 0,</p><p>` `"Archived": false</p><p>` `}]</p> |     |     |     |
|| 500           | Internal Server Error ||||     |     |     |     |
|| 404           | Not Found             ||||     |     |     |     |

## GET /auth2/groups
Returns a list of groups and the roles they contain

| **Parameters** | **Name** | **In** | **Description** | **Required** | **Type** |
|----------------|----------|--------|-----------------|--------------|----------|
| -              |


| **Responses** | **HTTP Status Code**  | **Description**                                                                         | **Schema** | **Headers** | **Example** |
|---------------|-----------------------|-----------------------------------------------------------------------------------------|------------|-------------|-------------|
|| 200           | Successful            ||| [{"Name":"reportviewer","Roles":["600"]},{"Name":"reportcreator","Roles":["500","501"]} |     |     |     |
|| 500           | Internal Server Error ||||     |     |     |     |
|| 404           | Not Found             ||||     |     |     |     |

## GET /auth2/hasactivedirectory
Indicates if we're using active directory.

| **Parameters** | **Name** | **In** | **Description** | **Required** | **Type** |
|----------------|----------|--------|-----------------|--------------|----------|
| -              |


| **Responses** | **HTTP Status Code** | **Description** | **Schema** | **Headers** | **Example** |
|---------------|----------------------|-----------------|------------|-------------|-------------|
|| 200           | Successful           ||| 1 = yes; 0 = no |     |     |     |
|| 404           | Not Found            ||||     |     |     |     |
