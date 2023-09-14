go build
imqsauth -c=.\testconf\imqsauth.json createdb
imqsauth -c=.\testconf\imqsauth.json resetauthgroups
imqsauth -c=.\testconf\imqsauth.json setgroup test pcssuperuser
imqsauth -c=.\testconf\imqsauth.json setgroup test2 enabled

imqsauth -c=.\testconf\imqsauth.json createuser test@test.com 12345
imqsauth -c=.\testconf\imqsauth.json permgroupadd test@test.com test
imqsauth -c=.\testconf\imqsauth.json permgroupadd test@test.com enabled

imqsauth -c=.\testconf\imqsauth.json createuser test2@test.com 12345
imqsauth -c=.\testconf\imqsauth.json permgroupadd test2@test.com test
imqsauth -c=.\testconf\imqsauth.json permgroupadd test2@test.com enabled
imqsauth -c=.\testconf\imqsauth.json permgroupadd test2@test.com admin
imqsauth -c=.\testconf\imqsauth.json permgroupadd test2@test.com test2

rem user with no permissions
imqsauth -c=.\testconf\imqsauth.json createuser test3@test.com 12345

