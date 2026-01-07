#!/usr/bin/python
# -*- encoding: utf-8 -*-
#

import smtplib
from smtplib import SMTP
import ssl

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.application import MIMEApplication

import logging
import logging
logger = logging.getLogger(__name__)

class MailSender:

    def __init__(self, host, port, login, password, fromWho):
      self.host = host
      self.port = port
      self.useStarttls=(port==587)
      self.fromWho = fromWho
      self.login = login
      self.password = password
      self.server = False
      self.content = ''

    def setContent(self, content):
      self.content=content

    def connect_test(self):
      # Do testów: Tworzymy kontekst, który nie weryfikuje certyfikatów
      ssl_context = ssl.create_default_context()
      ssl_context.check_hostname = False
      ssl_context.verify_mode = ssl.CERT_NONE
      self.server = SMTP(host=self.host, port=self.port)
      self.server.ehlo()  # Przywitanie przed TLS 
      if self.useStarttls:
          if self.server.has_extn("STARTTLS"):
              # Używamy zmodyfikowanego kontekstu 
              self.server.starttls(context=ssl_context)
              self.server.ehlo()  # Ponowne przywitanie po TLS, aby zobaczyć AUTH 
      self.server.login(user=self.login, password=self.password)

    def connect(self):
      ssl_context = ssl.create_default_context()
      self.server = SMTP(host=self.host, port=self.port)
      self.server.ehlo()  
      if self.useStarttls:
          # Wymuszamy STARTTLS jeśli port to 587
          self.server.starttls(context=ssl_context)
          self.server.ehlo()  # Ponowne przywitanie po TLS, aby zobaczyć AUTH
      self.server.login(user=self.login, password=self.password)    

    def disconnect(self):
        self.server.quit()
        self.server = False

    def sendMail(self, toWho, subject):
      logger.info('Send mail %s, %s' % (toWho, subject))
      if not self.server:
        self.connect()
      msg = MIMEMultipart()
      msg['To'] = toWho
      msg['From'] = self.fromWho
      msg['Subject'] = subject

      if self.content!=None:
        msg.attach( MIMEText(self.content.encode('utf-8'), 'plain', 'utf-8') )
      logger.info('Sendmail')
      print('wysylam')
      self.server.sendmail(self.fromWho, toWho, msg.as_string())


if __name__ == "__main__":
  email='user@example.com'
  host = "mail.example.com"
  port = 587
  sender_email = 'user@example.com'
  login = 'user@example.com'
  password =  'BArdZO_trudne234'
  subject= "testowa wiadomosc"
  content = 'testowa wiadomosc'
  try:
    logger.info('Sending process...')
    sender = MailSender(host, port, login, password,sender_email)
    sender.setContent(content)
    sender.connect_test()
    print('połączono')
    sender.sendMail( email, subject)
    print('Wysłano')
    sender.disconnect()
  except Exception as e:
    print(e)
    logger.info("Sending error: %s " % e)
