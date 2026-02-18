import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

class MTLSAdapter(HTTPAdapter):
    def __init__(self, cert_file, key_file, **kwargs):
        self.cert_file = cert_file
        self.key_file = key_file
        super().__init__(**kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.load_cert_chain(
            certfile=self.cert_file,
            keyfile=self.key_file
        )
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# Użycie
session = requests.Session()
session.mount('https://', MTLSAdapter('client.pem', 'client.key'))

response = session.get(
    'https://localhost:8443/',
    verify='ca/cacert.pem'  # Pełna weryfikacja łańcucha certyfikatów
)
print(response.text)
