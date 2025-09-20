#!/usr/bin/env python
# coding: utf-8
"""
e-Doręczenia - połączenia
"""
import base64
import json
from ua_model import FileMetadata, File, Attachment, MessagesWrapper, Message, Evidence

import uuid
from edr_token import request_token, post_auth_request
from edoreczenia import Edr

from config import settings
from unidecode import unidecode

def unix_name(name):
    return unidecode(str(name).replace(" ", "_"))

class EdrConnector():

  def __init__(self, test=False, search = False):
    if test:
      try:
        self.addr = settings.edr.address
        self.priv_key = settings.edr.key
        qtoken = request_token(self.addr, 'COLLECTOR', self.priv_key)
        (dtoken, code, hdr) = post_auth_request(qtoken, self.addr)
        self.token = dtoken['access_token']
      except Exception as e:
        print(e)
        print('Problem z tokenem')
        self.token = None
    else:
      try:
        self.addr = settings.edr.address
        fnpriv = settings.edr.key
        f=open(fnpriv)
        self.priv_key=f.read()
        f.close()
        qtoken = request_token(self.addr, settings.edr.system, self.priv_key)
        (dtoken, code, hdr) = post_auth_request(qtoken, self.addr)
        self.token = dtoken['access_token']
      except Exception as e:
        print(e)
        print('Problem z tokenem')
        self.token = None
    self.cert_subject=self.addr + '.SYSTEM.' + settings.edr.system
    self.edr=Edr(self.token,self.addr)

  def search(self, name, surname):
    res = self.edr.Szukaj(imie=name, nazwisko=surname)
    result = []
    jres = json.loads(res.data)
    try:
      for adres in jres['baeSearchData']:
        result.append({
          "name": adres["name"],
          "surname": adres["surname"],
          "professionalTitle": adres["professionalTitle"],
          "legalForm": adres["legalForm"],
          "designatedOperator": adres["designatedOperator"],
          "address": {"ade": adres["address"]["ade"],
                      "validFrom": adres["address"]["validFrom"],
                      "isMainAddress": adres["address"]["isMainAddress"]},
          "correspondenceAddress": adres["correspondenceAddress"]
        })
    except Exception as e:
      print(e)
    return result

  def send(self, ade, subject, body, atts=[]):
    a=[]
    order=1
    for att in atts:
      filename = unix_name(att['filename'])
      if filename[-4:]=='.zip':
        contentType='application/zip'
      elif filename[-4:]=='.txt':
        contentType='text/plain'
      elif filename[-4:]=='.rtf':
        contentType='application/rtf'
      elif filename[-4:]=='.pdf':
        contentType='application/pdf'
      elif filename[-4:]=='.xps':
        contentType='application/oxps, application/vnd.ms-xpsdocument'
      elif filename[-4:]=='.odt':
        contentType='application/vnd.oasis.opendocument.text'
      elif filename[-4:]=='.ods':
        contentType='application/vnd.oasis.opendocument.spreadsheet'
      elif filename[-4:]=='.odp':
        contentType='application/vnd.oasis.opendocument.presentation'
      elif filename[-4:]=='.doc':
        contentType='application/msword'
      elif filename[-4:]=='.xls':
        contentType='application/vnd.ms-excel'
      elif filename[-4:]=='.ppt':
        contentType='application/vnd.ms-powerpoint'
      elif filename[-5:]=='.docx':
        contentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      elif filename[-5:]=='.xlsx':
        contentType='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      elif filename[-5:]=='.pptx':
        contentType='application/vnd.openxmlformats-officedocument.presentationml.presentation'
      else:
        contentType = att['contentType'] if 'contentType' in att else 'application/pdf'
      metadata = FileMetadata( fileId=att['uuid'], \
                              filename=filename, \
                              contentType=contentType, \
                              description=att['description'] \
                              )
      file = File(fileMetadata=metadata, file=att['file64'])
      a.append(Attachment(AttachmentId=att['uuid'], order=order, file=file))
      order+=1
    try:
      ret = self.edr.SendMessage(ade, subject, body, a)

      try:
        msg = json.loads(ret.text)
        return msg
        # Przykład: '{"messageTaskId":"2153df8f-5f7c-4e7a-ae9c-e8c47add21cd"}'
      except:
        pass
      try:
        return {'MessageId': '',
                'AddresseeADE': '',
                'Status': 'error '+msg['error']+' '+msg["error_description"]
                }
      except:
        return {'MessageId': '',
                'AddresseeADE': '',
                'Status': 'error ?'}
    except Exception as e:
      return {'MessageId':'',
              'AddresseeADE':'',
              'Status':'error %s' %e}

  def inbox(self):
    result=[]
    try:
      messages: MessagesWrapper = self.edr.ListMessages(label='INBOX')
      for m in messages.messages:
        messageId = m.messageMetadata.messageId #m['messageMetadata']['messageId'].encode('ascii', 'ignore').decode('unicode_escape')
        result.append(messageId)
    except Exception as e:
      print(e)
    return result

  def sent(self):
    result = []
    try:
      messages: MessagesWrapper = self.edr.ListMessages(label='SENT')
      for m in messages.messages:
        messageId = m.messageMetadata.messageId  # m['messageMetadata']['messageId'].encode('ascii', 'ignore').decode('unicode_escape')
        result.append(messageId)
    except Exception as e:
      print(e)
    return result

  def message(self, messageId,format='fullExtended'):
    try:
      result : Message = self.edr.PobranieWiadomosciF(messageId,
                                                 format=format
                                                 # lub 'full': z załącznikami / z listą załączników (bez treści)
                                                 )
      """
      result = json.loads(ret.data.decode('utf-8'))
      if not ('receiptDate' in result['messageMetadata']):
        result['messageMetadata']['receiptDate']='2000-01-01T00:00:00.000Z'
      if not ('submissionDate' in result['messageMetadata']):
        result['messageMetadata']['submissionDate']='2000-01-01T00:00:00.000Z'
      """
      return result
    except Exception as e:
      print(e)
      return None

def ss(s):
  if s:
    return str(s)
  else:
    return ''

#############

def mime(fn):
  if fn[-4:]=='.jpg' or fn[-5:]=='jpeg':
    return 'image/jpeg'
  elif fn[-4:] == '.png':
    return 'image/png'
  elif fn[-5:] == '.webp':
    return 'image/webp'
  elif fn[-4:] == '.csv':
    return 'text/csv'
  elif fn[-4:] == '.xml':
    return 'text/xml'
  elif fn[-4:] == '.pdf':
    return 'application/pdf'
  elif fn[-4:] == '.txt':
    return 'text/plain'
  elif fn[-4:] == '.doc' or fn[-5:] == '.docx':
    return 'application/msword'
  return 'application/x-binary'

def  list_inbox(test=False):
  edrc=EdrConnector(test)
  lista_edr=edrc.inbox()
  try:
    for msgid in lista_edr:
        msg=edrc.message(msgid)
        print(msg)
        if msg:
          for a in msg.attachments:
            data = {
                #"content": a.file.file.decode(),
                "name": a.file.fileMetadata.filename,
                "description": a.file.fileMetadata.contentType,
              }
            print(data)
  except Exception as e:
    print('Błąd: %s' % e)

def test_send(ade,subject,body,att_filename,att_description):
  edrc=EdrConnector()
  try:
    if ade:
      if not subject:
        subject='Przesyłka'
      eatts=[]
      f = open(att_filename, 'rb')
      acontent = base64.b64encode(f.read()).decode()
      eatts.append( {
            'file64':acontent,
            'filename':att_filename,
            'contentType':mime(att_filename),
            'uuid':uuid.uuid4(),
            'description':att_description
        } )
      smsg=edrc.send(ade,subject,body,eatts)
      if 'Status' in smsg:
        print('Status='+smsg['Status'])
      if 'MessageId' in smsg:
        messageId=smsg['MessageId']
        print(messageId)
  except Exception as e:
    print('Błąd: %s' % e)
    return e.__str__()

# evidences (ZIP, XML, PDF)
def fetch_evidences_att(id, messageId, log=None):
  try:
      edrc = EdrConnector()
      zip=edrc.edr.PobranieDowodowZip(messageId)
      if zip:
        data = {
          "content": base64.b64encode(zip.data).decode('utf-8'),
          "name": 'evidences.zip',
          "description": 'Dowody techniczne (zip)',
        }
        print(data)

      d = edrc.edr.FetchEvidences(messageId)
      da = json.loads(d.data)
      if da:
        for e in da['Evidences']:
          if e['type'] == "BPOP" or e['type'] == 'BPWP':  # PDF doręczona or zaakceptowana
            epdf = edrc.edr.PobranieDowoduF(e['evidenceId'])
            data = {
              "content": base64.b64encode(epdf.data).decode('utf-8'),
              "name": e['type']+'.pdf',
              "description": 'Dowód '+('doręczenia' if e['type']=='BPOP' else 'odbioru'),
            }
            print(data)
          if e['type'] == 'BPWX' or e['type'] == 'BPOX':  # XML: Wiadomość zaakceptowana or pomyślnie preawizowana adresatowi
            exml = edrc.edr.PobranieDowoduF(e['evidenceId'])
            data = {
              "content": base64.b64encode(exml.data).decode('utf-8'),
              "name": e['type']+'.xml',
              "description": 'Dowód XML '+('zaakceptowania' if e['type']=='BPWX' else 'preawizowania'),
            }
            print(data)
  except Exception as e:
    if log:
      log.info('Exception webcon_update')
      log.info(e)
    else:
      print('Błąd: %s' % e)
  return None


def  fetch_evidences(msgid, test=False):
  try:
    edrc=EdrConnector(test)
    msg = edrc.message(msgid)
    for ev in msg.evidences:
      print(ev)
  except Exception as e:
    print('Błąd: %s' % e)

