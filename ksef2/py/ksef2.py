# ksef2.py

import argparse
import base64
import os
import time
import requests

from Crypto.Random import get_random_bytes

from ksef2client.invoice_utils import create_encryption_info, create_send_invoice_request, prepare_invoice_for_sending
from ksef2client.models import OpenOnlineSessionRequest, FormCode, OpenOnlineSessionResponse
from ksef2client.client import KSeFClient
from ksef2client.auth_utils import create_auth_request_xml2
from ksef2client.signing import sign_auth_request_with_xmlsec as sign_xades2


def authenticate_with_certificate_ksef2(ksef_client: KSeFClient, certificate_path: str, password: str, nip: str):
    """Poprawiona funkcja uwierzytelniania certyfikatem w KSeF 2.0."""
    try:
        # 1. Pobierz challenge
        print("1. Pobieranie challenge...")
        challenge_response = ksef_client.challenge()
        print(f"   Otrzymano challenge: {challenge_response.challenge}")

        # 2. Przygotuj XML do podpisania
        # POPRAWKA: Prawidłowa nazwa parametru to `identifier_value`
        auth_request_xml = create_auth_request_xml2(
            challenge=challenge_response.challenge,
            identifier_type="Nip",
            identifier_value=nip
        )

        # 3. Podpisz XML podpisem XAdES
        print("2. Podpisywanie żądania XML...")
        signed_xml = sign_xades2(auth_request_xml, certificate_path, password)

        # 4. Wyślij podpisany XML
        print("3. Inicjowanie uwierzytelniania podpisem...")
        init_response = ksef_client.auth_by_xades_signature(signed_xml)
        print(f"   Numer referencyjny operacji: {init_response.referenceNumber}")
        
        temp_auth_token = init_response.authenticationToken.token

        # 5. Sprawdzaj status operacji, aż do uzyskania statusu 200
        print("4. Sprawdzanie statusu operacji (oczekiwanie na kod 200)...")
        while True:
            # POPRAWKA: Funkcja auth_status w kliencie została usunięta, użyj generycznej `status`
            # i przekaż tymczasowy token w nagłówku.
            status_response = ksef_client.auth_status(init_response.referenceNumber, temp_auth_token)
            print(f"Aktualny status: {status_response.status.code} - {status_response.status.description}")
            
            if status_response.status.code == 200:
                break
            elif status_response.status.code >= 400:
                print(f"Uwierzytelnienie nie powiodło się. Powód: {status_response.status.description}")
                return None
            
            time.sleep(2)

        # 6. Wykup tokeny dostępowe
        print("5. Uwierzytelnianie zakończone. Wykupywanie tokenów sesji...")
        # POPRAWKA: `redeem_token` wymaga tylko `temp_auth_token`, numer referencyjny jest w tokenie
        tokens = ksef_client.redeem_token(temp_auth_token)
        
        # 7. Ustaw główny token dostępu w kliencie
        ksef_client.set_access_token(tokens.accessToken.token)
        print("Tokeny pobrane. Token dostępu został ustawiony w kliencie.")
        
        return tokens

    except requests.exceptions.HTTPError as e:
        print(f"Wystąpił błąd HTTP: {e.response.status_code}")
        print(f"Treść odpowiedzi: {e.response.text}")
        return None
    except Exception as e:
        print(f"Wystąpił nieoczekiwany błąd: {e}")
        return None

def get_mf_public_key(ksef_client: KSeFClient, usage: str = "SymmetricKeyEncryption") -> str:
    """Pobiera i konwertuje aktualny klucz publiczny MF."""
    try:
        public_keys = ksef_client.get_public_keys()
        for key in public_keys:
          for u in key.usage:
            if usage == u.value:
                der_cert = base64.b64decode(key.certificate)
                return convert_der_to_pem(der_cert)
        raise Exception(f"Nie znaleziono klucza publicznego dla użycia: {usage}")
    except Exception as e:
        raise Exception(f"Błąd pobierania klucza publicznego MF: {e}")

def convert_der_to_pem(der_data: bytes) -> str:
    """Konwertuje certyfikat z formatu DER do PEM."""
    pem_data = base64.b64encode(der_data).decode('ascii')
    pem_lines = [f"-----BEGIN CERTIFICATE-----"]
    pem_lines.extend(pem_data[i:i + 64] for i in range(0, len(pem_data), 64))
    pem_lines.append(f"-----END CERTIFICATE-----")
    return "\n".join(pem_lines)

def ksef2_open_online_session(ksef_client: KSeFClient, public_key_pem: str) -> tuple[OpenOnlineSessionResponse, bytes, bytes]:
    """
    Otwiera sesję online, wysyła żądanie do KSeF i zwraca odpowiedź serwera
    oraz użyty klucz symetryczny i IV.
    """
    # POPRAWKA: Cała funkcja została przepisana, aby faktycznie wysyłać żądanie
    symmetric_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    
    encryption_info = create_encryption_info(symmetric_key, public_key_pem, iv)
    
    session_request = OpenOnlineSessionRequest(
        formCode=FormCode(systemCode="FA (2)", schemaVersion="1-0E", value="FA"),
        encryption=encryption_info
    )
    
    # Wywołanie klienta w celu otwarcia sesji
    session_response = ksef_client.online_session_open(session_request)
    
    # Zwracamy odpowiedź serwera oraz klucz i IV do późniejszego użycia
    return session_response, symmetric_key, iv

def ksef2_send_invoice_in_session(ksef_client: KSeFClient, session_ref: str, invoice_data: bytes, symmetric_key: bytes, iv: bytes):
    """
    Szyfruje i wysyła fakturę w ramach już otwartej sesji, używając podanego klucza.
    """
    # POPRAWKA: Ta funkcja teraz używa klucza i IV z otwartej sesji, a nie generuje nowych
    
    # Szyfrowanie faktury z użyciem klucza sesji
    encrypted_content, _, _ = prepare_invoice_for_sending(invoice_data, symmetric_key, iv)

    # Utwórz request - EncryptionInfo nie jest potrzebne, bo jest już w sesji
    send_request = create_send_invoice_request(
        xml_content=invoice_data,
        encrypted_xml_content=encrypted_content,
        encryption_info=None, # Nie jest wymagane przy wysyłce faktury
        offline_mode=False
    )
    
    return ksef_client.online_session_send_invoice(session_ref, send_request)


def test_send_invoice_flow(nip: str, invoice_path: str, certificate_path : str, password: str):
    """Kompletny, poprawny przepływ uwierzytelniania i wysyłki faktury."""
    ksef = KSeFClient(base_url="https://ksef-test.mf.gov.pl")
    
    print("--- Krok 1: Uwierzytelnianie ---")
    tokens = authenticate_with_certificate_ksef2(
        ksef,
        nip=nip,
        certificate_path=certificate_path,
        password=password
    )
    if not tokens:
        return
    
    print("\n--- Krok 2: Pobieranie klucza publicznego MF ---")
    try:
        public_key = get_mf_public_key(ksef, "SymmetricKeyEncryption")
        print("   Klucz publiczny pobrany pomyślnie.")
    except Exception as e:
        print(f"   Błąd pobierania klucza: {e}")
        return

    session_ref = None
    try:
        print("\n--- Krok 3: Otwieranie sesji interaktywnej ---")
        session_response, sym_key, iv = ksef2_open_online_session(ksef, public_key)
        session_ref = session_response.referenceNumber
        print(f"   Sesja otwarta, numer referencyjny: {session_ref}")

        print("\n--- Krok 4: Wysyłanie faktury ---")
        with open(invoice_path, "rb") as f:
            invoice_data = f.read()
        
        send_response = ksef2_send_invoice_in_session(ksef, session_ref, invoice_data, sym_key, iv)
        print(f"   Faktura wysłana, numer referencyjny faktury: {send_response.referenceNumber}")

    except Exception as e:
        print(f"   Wystąpił błąd podczas wysyłki: {e}")
    finally:
        if session_ref:
            print("\n--- Krok 5: Zamykanie sesji ---")
            ksef.online_session_terminate(session_ref)
            print("   Sesja została zamknięta.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Testowanie klienta KSeF 2.0')
    parser.add_argument('cmd', choices=['login', 'send'], help='Operacja do wykonania.')
    parser.add_argument('--nip', required=True, help='NIP podatnika.')
    
    args = parser.parse_args()

    if args.cmd == 'login':
        ksef_client = KSeFClient(base_url="https://ksef-test.mf.gov.pl")
        authenticate_with_certificate_ksef2(
            ksef_client,
            nip=args.nip,
            certificate_path=os.path.join(os.path.dirname(__file__), 'cert.pfx'),
            password='pass123'
        )
    elif args.cmd == 'send':
        invoice_file_path = os.path.join(os.path.dirname(__file__), 'invoice.xml')
        test_send_invoice_flow(args.nip, invoice_file_path,
                               certificate_path=os.path.join(os.path.dirname(__file__), 'cert.pfx'),
                               password='pass123')