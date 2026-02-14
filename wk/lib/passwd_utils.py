# !/usr/bin/python
# -- coding: utf-8 --
# rfc7519
import datetime
import json

from cryptography.fernet import Fernet
import time
#from passlib.hash import md5_crypt, nthash
import string, random
import logging
# from lib.mail_utils import send
from lib.mail_utils import MailSender
from core.config import settings

import logging
logger = logging.getLogger(__name__)

jwtexpireoffset=datetime.timedelta(days=7).total_seconds()
jwtalgorithm='HS256'

class Error(Exception):
    pass

def escape(s):
 return s.replace(' ', '\\ ')

def password_generator():
  digit_len = random.randint(2, 3)
  upper_len = random.randint(2, 3)
  min=8-(digit_len+upper_len)
  if min<2:
    min=2
  max=min+2
  length = digit_len+upper_len+random.randint(min, max)

  upper = string.ascii_uppercase                   # A-Z
  digits = string.digits                           # 0-9
  letters = string.ascii_lowercase                 # a-z

  password = []
  last = ''

  while len(password) < upper_len:
    choice = random.choice(upper)
    if choice != last:
        password.append(choice)
        last = choice

  while len(password) < upper_len+digit_len:
    choice = random.choice(digits)
    if choice != last:
        password.append(choice)
        last = choice

  while len(password) < length:
    choice = random.choice(letters)
    if choice != last:
        password.append(choice)
        last = choice

  random.shuffle(password)

  return ''.join(password)

def json_token(sub,email):  # define decoded token
  return {'email': email,  # user
          'sub': sub,  # action
          'exp': time.time() + jwtexpireoffset}

def jwt_decode(token):
  if token:
    fernet = Fernet(settings.app.secretkey)
    return json.loads(fernet.decrypt(token.encode()).decode())
  else:
    return json_token({'email': '', 'sub': '1', 'exp': 0})

def jwt_encode(decoded_token):
  fernet = Fernet(settings.app.secretkey)
  btoken = bytes(json.dumps(decoded_token).encode())
  token=fernet.encrypt(btoken).decode()
#  print(jwt_decode(token))
  return token

def check_password(token, new_password, confirm_password):
  try:
    token_decoded = jwt_decode(token)
    email = token_decoded['email']
    action = token_decoded['sub']
    exp = int(token_decoded['exp'])
  except Exception as e:
    return 'Internal error: %s' % e
  if time.time() > exp:
    return "Token expiried!"
  if (action != '51' and action != '52' and action != '53') or (not email):
    return "Bad token!"
  if new_password  !=  confirm_password:
    return "Password doesn't match the confirmation!"
  if len(new_password) < 8:
    return "Password must be at least 8 characters long!"
  return 'OK'

def url_t1(email):
  return settings.app.fronend_url+'/s?t='+jwt_encode(json_token('51',email))

def url_send_mail(email, url):
  subject='wkdemo: Reset hasła - link'
  logger.info('Send from ' + settings.smtp.sender+ 'to '+email)
  sender = MailSender(settings.smtp.server, settings.smtp.port, settings.smtp.login, settings.smtp.password, settings.smtp.sender)
  sender.setContent(url)
  try:
    logger.info('Sending process...')
    sender.connect()
    sender.sendMail(email, subject)
    sender.disconnect()
    logger.info('Sended.')
  except Exception as e:
    logger.info("Sending error: %s " % e)
    return "Sending error: %s " % e
  return 'OK'

def send_url_token(email):
  url_send_mail(email, url_t1(email))

if __name__ == '__main__':
  print(url_t1('test@example.com'))
  token=jwt_encode(json_token('51','test@example.com'))
  print(token)
  print(check_password(token, 'abcdes', 'abcdef'))
  print(check_password(token, 'abcdef', 'abcdef'))
  print(check_password(token, 'abcdef12', 'abcdef12'))