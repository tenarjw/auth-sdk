#!/usr/bin/python3
# coding: utf-8

from local_server import runHTTPServer, acode
import threading
import requests
from pprint import pprint
import json
#from manager import uuid

authority_url = 'http://localhost:8088/oauth/authorize'
token_url = 'http://localhost:8088/oauth/token'
api_port=8088
auth_url='http://localhost:8088/oauth/authorize'
server_ip='127.0.0.1'
server_port=3000

#redirect_url='http://127.0.0.1:3000'
redirect_uri='http%3A%2F%2F127.0.0.1%3A'+str(server_port)
client_id='9a195ac5-1a34-4bdd-837e-13f80bc5364d'
print('Check client_id (../manage_py --id=1 uuid):')
code_url=auth_url+('?redirect_uri=%s&client_id=%s' % (redirect_uri,client_id))+\
             '&response_type=code&state=state_test&response_mode=query'

class TestApp:
  def __init__(self):
    self.config={}
    self.config["client_id"]='9a195ac5-1a34-4bdd-837e-13f80bc5364d' #uuid(1)
    self.config["scope"]=''
    self.ip=server_ip
    self.port=server_port
    self.config["redirect_uri"]='http://%s:%s' % (server_ip,server_port)

  def get_token(self, code):
    params = {
          'grant_type': 'authorization_code',
          'response_type': 'token',
          'code': code,
          'client_id': self.config["client_id"],
          'scope': self.config["scope"],
          'redirect_uri': self.config["redirect_uri"]
      }
    try:
      resp = requests.post(token_url, params)
      respdata = json.loads(resp.text)
      if 'access_token' in respdata:
        self._access_token=respdata['access_token']
        return self._access_token
      else:
        pprint(respdata)
        return None

    except Exception as e:
      print(e)
      return None

  def run_query(self, query, req_method, headers=None, req_body=None):
      if not self._access_token:
        print('Brak tokenu')
        return
      req_headers = {
          'Authorization': 'Bearer ' + self._access_token,
          'Accept': '*/*',
          'Content-Type': 'application/json'
      }
      if headers:
          for key in headers:
              req_headers[key] = headers[key]
      data = None
      if req_method == "POST":
          data = requests.post(query, headers=req_headers,
                               json=json.dumps(req_body)).json()
      if req_method == "GET":
          data = requests.get(query, headers=req_headers)
      if req_method == "PUT":
          data = requests.put(query, data=req_body, headers=req_headers).json()
      return data

  def get_test(self):
    test_endpoint=''
    body = {
      }
    self.run_query(test_endpoint, "POST", None, body)

def start_httpd(ip,port):
  runHTTPServer(ip,port)

def server_thread():
    start_httpd(server_ip, server_port)

try:
    thread_type = threading.Thread(target=server_thread)
    thread_type.start()
    thread_type.join(2)
    demo_login = {"username": "demo", "password": "demo"}
    session = requests.Session()
    login = session.post(
      f'http://localhost:{api_port}/login_json',
      data=demo_login
    )
    print(login.status_code)
    print(login.json())
    cookies=session.cookies.get_dict()
    response=session.get(code_url, cookies=cookies)
    #curl -X 'GET' \
#  'http://localhost:8088/oauth/authorize?client_id=1&redirect_uri=http%3A%2F%2Flocalhost%3A3000&response_type=code&response_mode=fragment' \
 # -H 'accept: application/json'
    code=0
    try:
      global acode
      code=acode[0]
      pprint(response.text)
      print('code=',code)
    except Exception as e:
      print(e)
    if code:
      my_app = TestApp()
      token=my_app.get_token(code)
      print('token=',token)
#      if token:
#        print(my_app.get_test())
    print('koniec testu')
except Exception as e:
    print("Error: %s" % e)
