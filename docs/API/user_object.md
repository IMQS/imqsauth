# GET /userobject

Returns a singular user object containing user data and authorisation.

## Query Parameters

| Param  | Description                                       |
| ------ | ------------------------------------------------- |
| userid | id of the user whose details are requested     |
| identity  | email/username of the user whose details are requested  |

## Structs

### userResponseJson

```go
type userResponseJson struct {
    UserId        authaus.UserId
    Email         string
    Username      string
    Name          string
    Surname       string
    Mobile        string
    Telephone     string
    Remarks       string
    Created       time.Time
    CreatedBy     string
    Modified      time.Time
    ModifiedBy    string
    Groups        []string
    AuthUserType  authaus.AuthUserType
    Archived      bool
    AccountLocked bool
    InternalUUID  string
}
```

## Example

```JSON
{
   "UserId": 3550,
   "Email": "user1@gmail.com",
   "Username": "user1",
   "Name": "User1",
   "Surname": "User1",
   "Mobile": "",
   "Telephone": "",
   "Remarks": "",
   "Created": "2019-06-12T15:08:09.4552Z",
   "CreatedBy": "Administrator",
   "Modified": "2019-06-12T15:08:46.764303Z",
   "ModifiedBy": "Dev Dev",
   "Groups": ["enabled"],
   "AuthUserType": 0,
   "Archived": false
}
```
