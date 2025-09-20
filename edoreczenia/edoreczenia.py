#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

import json
from datetime import datetime


from api_generated import EvidencesApi, MessagesApi, SubscriptionsApi, SearchEngineApi, AttachmentsApi, ApiClient
from se_model import BaeSearch
from ua_model import Attachment, MessageMetadata, Message, MessagesWrapper, MessageControlData, \
  File, Evidence, MessageAddressData, Type

from pydantic import BaseModel, ValidationError
from uuid import UUID,uuid1

class Edr():

  def __init__(self, access_token, myDeliveryAddress):
    self.access_token=access_token
    self.myDeliveryAddress=myDeliveryAddress
    self.api_client=ApiClient(access_token)

  def ListMessages(self,
                   label='.',  # Folder do pobrania listy wiadomości
                   submissionDateFrom=None,  # Data od dla pola submissionDate
                   submissionDateTo=None,  # Data do dla pola submissionDate.
                   receiptDateFrom=None,  # Data otrzymania od
                   receiptDateTo=None,  #Data otrzymania do
                   ) -> MessagesWrapper:
    # -> BaseModel
    """
    Przykład treści poprawnej odpowiedzi (200 - OK)
        {
        "messages": [
        {
        "messageControlData": {
        "status": "INBOX",
        "MessageType": "Message",
        "labels": [
        {
        "label": "INBOX"
        }
        ]
        },
        "messageMetadata": {
        "from": {
        "myDeliveryAddress": "AE:PL-00000-00013-AAAAA-06"
        },
        "to": [
        {
        "myDeliveryAddress": "AE:PL-00000-00014-AAAAA-05"
        }
        ],
        "subject": "Przykładowy temat wiadomości",
        "messageId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
        "threadId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
        "receiptDate": {},
        "submissionDate": {},
        "shippingService": "electronic"
        },
        "textBody": "Przykładowa treść wiadomości"
        }
        ]
        }
    """
    api=MessagesApi(self.api_client)
    response=api.getMessages(self.myDeliveryAddress,
                           label=label,
                           submissionDateFrom=submissionDateFrom,
                           submissionDateTo=submissionDateTo,
                           receiptDateFrom=receiptDateFrom,
                           receiptDateTo=receiptDateTo,
                           _preload_content=False, # !!!! próba rozpakowania -> błąd
                             )

    model: type[BaseModel] = MessagesWrapper
    try:
      data = json.loads(response.text)
      if model:
        return model(**data)
      else:
        return None
    except json.JSONDecodeError as e:
      raise ValueError(f"Błąd dekodowania JSON: {e}")
    except ValidationError as e:
      raise ValueError(f"Błąd walidacji modelu: {e}")


  def FetchMessages(self,
                    messageId,
                    format='fullExtended'  # lub 'full': z załącznikami / z listą załączników (bez treści)
                    ) -> Message:
    """
  Przykład treści poprawnej odpowiedzi (200 - OK)
  {
  "messageControlData": {
  "status": "INBOX",
  "MessageType": "Message",
  "labels": [
  {
  "label": "INBOX"
  }
  ]
  },
  "messageMetadata": {
  "from": {
  "myDeliveryAddress": "AE:PL-00000-00013-AAAAA-06"
  },
  "to": [
  {
  "myDeliveryAddress": "AE:PL-00000-00014-AAAAA-05"
  }
  ],
  "subject": "Przykładowy temat wiadomości",
  "messageId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
  "threadId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
  "receiptDate": {},
  "submissionDate": {},
  "shippingService": "electronic"
  },
  "textBody": "Przykładowa treść wiadomości"
  }
    """
    api = MessagesApi(self.api_client)
    response=api.getMessage(self.myDeliveryAddress, messageId, format=format,
                          _preload_content=False  # !!!! próba rozpakowania -> błąd
                        )
    #model: type[BaseModel] = Message
    try:
      data = json.loads(response.text)
      m=Message(
        messageControlData = MessageControlData(**data['messageControlData']),
        messageMetadata = MessageMetadata(**data['messageMetadata']),
        textBody=data['textBody'],
        attachments=[],
        evidences=[]
      )
      for a in data['attachments']:
        if not 'fileId' in a['file']['fileMetadata']:
          a['file']['fileMetadata']['fileId']=uuid1()
        m.attachments.append(Attachment(
          #order=a['order'],
          attachmentId=UUID(a['attachmentId']),
          file=File(**a['file'])))
      for ev in data['evidences']:
        m.evidences.append(Evidence(
          evidenceId=ev['evidenceId'] ,
          messageId=ev['messageId'],
          createDate=datetime.fromisoformat(ev['createDate']),
          eventDate=datetime.fromisoformat(ev['eventDate']),
          reasonDetails=[rd  for rd in ev['reasonDetails']],
         #reasonId=ev['reasonId'],
          externalData=ev['externalData'],
          downloaded=ev['downloaded'],
          type=Type(ev['type']),
          from_= MessageAddressData(**ev['from']),
          to=MessageAddressData(**ev['to'])
        ))
      return m
    except json.JSONDecodeError as e:
      raise ValueError(f"Błąd dekodowania JSON: {e}")
    except ValidationError as e:
      raise ValueError(f"Błąd walidacji modelu: {e}")


  def FetchEvidences(self, messageId, **kwargs):
      """
      Przykład treści poprawnej odpowiedzi (200 - OK)
  {
  "evidences": [
  {
  "evidenceId": "830f6d4c-5e77-4e2e-a305-f8678acb49e0",
  "messageId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
  "createDate": "2021-06-30T13:01:22.268462Z",
  "externalData": "http://poczta-polska.pl/edor/AE:PL-13447-72418-ECVIU-
  30/evidences/qerds/34e09d5b-4965-4943-970c-c26549d7f623",
  "type": "A.1"
  }
  ]
  }   """
      api=EvidencesApi(self.api_client)
      return api.getEvidencesForMessage(self.myDeliveryAddress, messageId,
                                        _preload_content=False, # !!!! próba rozpakowania -> błąd (models w api_client w.269
                                         **kwargs)

  def FetchEvidence(self, evidenceId, **kwargs):
      """
      Przykład treści poprawnej odpowiedzi (200 - OK)
  {
  "evidenceId": "830f6d4c-5e77-4e2e-a305-f8678acb49e0",
  "messageId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
  "createDate": "2021-06-30T13:01:22.268462Z",
  "externalData": "http://poczta-polska.pl/edor/AE:PL-13447-72418-ECVIU-
  30/evidences/qerds/34e09d5b-4965-4943-970c-c26549d7f623",
  "type": "A.1"
  }
      """
      api=EvidencesApi(self.api_client)
      return api.getEvidence(self.myDeliveryAddress, evidenceId,
                             _preload_content=False,  # !!!! próba rozpakowania -> błąd (models w api_client w.269
                             **kwargs)


  def PobranieDowodowZip(self, messageId, **kwargs):
    api = EvidencesApi(self.api_client)
    return api.getZipEvidences(self.myDeliveryAddress,messageId,
                           _preload_content=False,  # !!!! próba rozpakowania -> błąd (models w api_client w.269
                           **kwargs)


  #
  def SendMessage(self, eDeliveryAddress, subject, textBody, attachments, recipient=''):
    """
    Przykład treści poprawnego żądania:
  {
  "messageControlData": {
  "MessageType": "Message"
  },
  "messageMetadata": {
  "to": [
  {
  "eDeliveryAddress": "AE:PL-00000-00014-AAAAA-05"
  }
  ],
  "subject": "Przykładowy temat wiadomości",
  "shippingService": "electronic"
  },
  "textBody": "Przykładowa treść wiadomości",
  "attachments": [
  {
  "order": 0,
  "attachmentId": "D41568F4-7175-42BB-9503-DAA282180D70",
  "file": {
  "fileMetadata": {
  "fileId": "D41568F4-7175-42BB-9503-DAA282180D70",
  "filename": "document.txt",
  "contentType": "text/plain",
  "size": 16732,
  "alg": "SHA-3",
  "hash":
  "MmJiMzE0ZjUxODU0NGIyZTk4MGQ5MGRjMWIyMDU1YjJlMzJlODAxNjQ3MzA0YzMxZjQxZDM4NW
  NlNGU2ODc3YjZkMDcxZjE4NGEwMGUyZGI3N2ZiZjMyYzA0OTAwYjE4ZWU2OTI3NjIyNDRjYmZhY2Ew
  NjMxNzQ2M2Y2Y2U5M2I=",
  "description": "Text document"
  },
  "file": "{base64Encodeded}"
  }
  }
  ]
  }

  =========================
  Przykład treści poprawnej odpowiedzi (200 - OK)
  {
  "Messages": [
  {
  "messageId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
  "AddresseeADE": "AE:PL-13447-72418-ECVIU-30",
  "Status": "SUCCESS"
  }
  ]
  }
    """
    body={
         "messageControlData": { "MessageType": "Message"  },
          "messageMetadata": {
            "from": {"eDeliveryAddress":self.myDeliveryAddress
              #, "contributor": {"companyName": 'Państwowa Kademia Nauk Stosowanych w Przemyślu'}
            },
            "to": [
             { "eDeliveryAddress": eDeliveryAddress,
               "contributor":{"companyName":recipient}}
                #"contributor":{"firstName": "YMER", "lastName": "ZGODOWSKI"}},
             ],
          "subject": subject,
          "shippingService": "electronic"
         },
        "textBody": textBody,
        "attachments": []
    }
    for a in attachments:
        aa=json.loads(a.model_dump_json())
        body['attachments'].append(aa)
    api = MessagesApi(self.api_client)
    result = api.postMessage(body, self.myDeliveryAddress,
                             _preload_content=False,  # !!!! próba rozpakowania -> błąd (models w api_client w.269
                             )
    return result


  def PobranieWiadomosciF(self,
                         messageId,
                         format='fullExtended' # lub 'full': z załącznikami / z listą załączników (bez treści)
                         )->Message:
    """
  Przykład treści poprawnej odpowiedzi (200 - OK)
  {
  "messageControlData": {
  "status": "INBOX",
  "MessageType": "Message",
  "labels": [
  {
  "label": "INBOX"
  }
  ]
  },
  "messageMetadata": {
  "from": {
  "myDeliveryAddress": "AE:PL-00000-00013-AAAAA-06"
  },
  "to": [
  {
  "myDeliveryAddress": "AE:PL-00000-00014-AAAAA-05"
  }
  ],
  "subject": "Przykładowy temat wiadomości",
  "messageId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
  "threadId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
  "receiptDate": {},
  "submissionDate": {},
  "shippingService": "electronic"
  },
  "textBody": "Przykładowa treść wiadomości"
  }
    """
    api = MessagesApi(self.api_client)
    response=api.getMessage(self.myDeliveryAddress, messageId, format=format,
                          _preload_content=False # !!!! próba rozpakowania -> błąd
                        )
    try:
      data = json.loads(response.text)
      if type(data)==list: # miana w API
        m=Message(**data[0])
      else:
        m = Message(**data)
      return m
    except json.JSONDecodeError as e:
      raise ValueError(f"Błąd dekodowania JSON: {e}")
    except ValidationError as e:
      raise ValueError(f"Błąd walidacji modelu: {e}")
    except Exception as e:
      raise ValueError(f"Nieznany błąd modelu: {e}")


  def PobranieDowodowF(self, messageId, **kwargs):
      """
      Przykład treści poprawnej odpowiedzi (200 - OK)
  {
  "evidences": [
  {
  "evidenceId": "830f6d4c-5e77-4e2e-a305-f8678acb49e0",
  "messageId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
  "createDate": "2021-06-30T13:01:22.268462Z",
  "externalData": "http://poczta-polska.pl/edor/AE:PL-13447-72418-ECVIU-
  30/evidences/qerds/34e09d5b-4965-4943-970c-c26549d7f623",
  "type": "A.1"
  }
  ]
  }   """
      api=EvidencesApi(self.api_client)
      return api.getEvidencesForMessage(self.myDeliveryAddress, messageId,
                                        _preload_content=False, # !!!! próba rozpakowania -> błąd (models w api_client w.269
                                        **kwargs)

  def PobranieDowoduF0(self, evidenceId, **kwargs):
      """
      Przykład treści poprawnej odpowiedzi (200 - OK)
  {
  "evidenceId": "830f6d4c-5e77-4e2e-a305-f8678acb49e0",
  "messageId": "ed28de2d-2b93-40ce-be55-ff260475f08e",
  "createDate": "2021-06-30T13:01:22.268462Z",
  "externalData": "http://poczta-polska.pl/edor/AE:PL-13447-72418-ECVIU-
  30/evidences/qerds/34e09d5b-4965-4943-970c-c26549d7f623",
  "type": "A.1"
  }
      """
      api=EvidencesApi(self.api_client)
      return api.getEvidence(self.myDeliveryAddress, evidenceId,
                             _preload_content=False,  # !!!! próba rozpakowania -> błąd (models w api_client w.269
                             **kwargs)

  def PobranieDowoduF(self, evidenceId, **kwargs):
      api=EvidencesApi(self.api_client)
      return api.getEvidence(self.myDeliveryAddress, evidenceId,
                             _preload_content=False,  # !!!! próba rozpakowania -> błąd (models w api_client w.269
                             **kwargs)

  def DefiniujSubskrypcje(self, eDeliveryAddress, messageCallback,evidenceCallback,inboxCallback):
    api = SubscriptionsApi(self.api_client)
    body={
    #    "eDeliveryAddress": eDeliveryAddress,
        "messageCallbackUrl": messageCallback,
        "evidenceCallbackUrl": evidenceCallback,
        "inboxCallbackUrl": inboxCallback
    }
    result = api.putSubscriptions(eDeliveryAddress, body=body)
    return result

  def UsunWiadomosc( self, messageId ):
    api=MessagesApi(self.api_client)
    result=api.deleteMessage(self.myDeliveryAddress,messageId)
    return result


  def PobierzZalacznik(self,
                         messageId,
                         att_id
                         ):

    api = AttachmentsApi(self.api_client)
    (result, code, headers)=api.getMessageAttachment(self.myDeliveryAddress, messageId, att_id)
    if code==200:
        try:
            return (result.data,200)
        except Exception as e:
            print(e)
            return (None,200)
    else:
        return (result, code)

############## szukanie #####################

  def SzukajEDA(self, reda, eda='AE:PL-25888-20449-HTFCF-29' ):
    bs={"recipientEdas":[reda],
        "senderEda":eda,"offset":0, "limit":2}
    api = SearchEngineApi(self.api_client)
    result = api.SearchBAE2(bs)
    return result

  def SzukajOsoby(self, name, surname, pesel='', city='', buildingNumber='',\
                  eda='AE:PL-25888-20449-HTFCF-29' ):
    if pesel != '':
        bs={"name":name,"senderEda":eda,
              "searchCategory":["INDIVIDUAL"],
              "surname":surname,
              "officialIds":[{"id":pesel,"referenceRegistry":"pesel"}],
              "limit":20}
    else:
        bs=  {"name":name,"senderEda":eda,
              "searchCategory":["INDIVIDUAL"],
              "surname":surname,
              "address":[{"addressType":["correspondence","headquarters"],
              "countryCode":"PL","city":city,"buildingNumber":buildingNumber,
              "country":{"id":"PL","label":"POLSKA","name":"POLSKA"}}],"limit":20}
    api = SearchEngineApi(self.api_client)
    result = api.SearchBAE1(bs)
    return result

  def SzukajInstytucji(self, pesel='', nip='', regon='', krs='', name='', address={},\
                  eda='AE:PL-25888-20449-HTFCF-29' ):
    if pesel != '':
      bs = {"senderEda": eda,
            "searchCategory": ["COMPANY", "ORGANISATION", "PUBLIC_INSTITUTION"],
            "officialIds": [{"id": pesel, "referenceRegistry": "pesel"}],
            "limit": 20}
    elif regon != '':
        bs = {"senderEda": eda,
              "searchCategory": ["COMPANY", "ORGANISATION", "PUBLIC_INSTITUTION"],
              "officialIds": [{"id": regon, "referenceRegistry": "regon"}],
              "limit": 20}
    elif nip != '':
        bs = {"senderEda": eda,
              "searchCategory": ["COMPANY", "ORGANISATION", "PUBLIC_INSTITUTION"],
              "officialIds": [{"id": nip, "referenceRegistry": "nip"}],
              "limit": 20}
    elif krs != '':
        bs = {"senderEda": eda,
              "searchCategory": ["COMPANY", "ORGANISATION", "PUBLIC_INSTITUTION"],
              "officialIds": [{"id": krs, "referenceRegistry": "krs"}],
              "limit": 20}
    else:
        bs= {"senderEda": eda,
             "searchCategory": ["COMPANY", "ORGANISATION", "PUBLIC_INSTITUTION"],
             "entityName":name,
             "address":[address,],
             "limit": 20}
        bs['address'][0]['addressType']=["correspondence","headquarters"]
        bs['address'][0]['country']={"id":"PL","label":"POLSKA","name":"POLSKA"}
    api = SearchEngineApi(self.api_client)
    result = api.SearchBAE1(bs)
    return result

