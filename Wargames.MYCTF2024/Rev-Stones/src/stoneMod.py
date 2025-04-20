import requests
from datetime import datetime
from urllib.request import urlopen
from datetime import datetime

date = '2022-07-25'

server_url = 'http://13.58.69.212:8000/'
# if current_date == local_date:
#     print("We're gonna need a really big brain; bigger than his?")
first_flag = 'WGMY{1d2993'
params = {'first_flag': first_flag, 'date': date}
response = requests.get(server_url, params=params)
if response.status_code == 200:
    print(response.json()['flag'])
else:
    print(response.json()['error'])