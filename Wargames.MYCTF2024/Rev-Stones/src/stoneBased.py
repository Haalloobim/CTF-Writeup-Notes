import requests
from datetime import datetime
from urllib.request import urlopen
from datetime import datetime
server_url = 'http://13.58.69.212:8000/'
current_time = urlopen('http://just-the-time.appspot.com/')
current_time = current_time.read().strip()
current_time = current_time.decode('utf-8')
current_date = current_time.split(' ')[0]
local_date = datetime.now().strftime('%Y-%m-%d')
if current_date == local_date:
    print("We're gonna need a really big brain; bigger than his?")
first_flag = 'WGMY{1d2993'
user_date = current_date
params = {'first_flag': first_flag, 'date': user_date}
response = requests.get(server_url, params=params)
if response.status_code == 200:
    print(response.json()['flag'])
else:
    print(response.json()['error'])

