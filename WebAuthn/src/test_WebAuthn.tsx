// Pomocnicze funkcje konwersji danych
export function uint8ArrayToBase64url(data: ArrayBuffer): string {
  const bytes = new Uint8Array(data);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlToUint8Array(base64url: string): Uint8Array {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const array = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) array[i] = raw.charCodeAt(i);
  return array;
}

// REJESTRACJA klucza w przeglądarce (create) ---
export async function registerWebAuthnTest(): Promise<string> {
  if (!window.PublicKeyCredential) {
    throw new Error('WebAuthn nie jest wspierany w tej przeglądarce');
  }
  // do testów generujemy challenge i userId lokalnie, zamiast pobierać z serwera
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge,
    rp: {
      name: 'Test lokalny',
      id: window.location.hostname, // ważne: ta sama domena co przy logowaniu
    },
    user: {
      id: userId,
      name: 'test@localhost',
      displayName: 'Testowy użytkownik',
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },   // ES256 (zalecany)
      { type: 'public-key', alg: -257 }, // RS256 (dla starszych kluczy)
    ],
    authenticatorSelection: {
      userVerification: 'preferred',
    },
    timeout: 60_000,
    attestation: 'none', // w testach nie potrzebny
  };

  try {
    const credential = (await navigator.credentials.create({
      publicKey,
    })) as PublicKeyCredential;
    if (!credential) throw new Error('Rejestracja przerwana');
    const response = credential.response as AuthenticatorAttestationResponse;
    // Zapisujemy credential ID lokalnie, używamy przy logowaniu
    const credentialId = uint8ArrayToBase64url(credential.rawId);
    localStorage.setItem('test_webauthn_credential_id', credentialId);
    console.log('Rejestracja udana!');
    console.log('Attestation response:', response);
    return credentialId;
  } catch (err: any) {
    console.error('Błąd podczas rejestracji:', err);
    throw err;
  }
}

// --- LOGOWANIE (get) ---
export async function loginWebAuthnTest(): Promise<void> {
  const storedCredentialId = localStorage.getItem('test_webauthn_credential_id');
  if (!storedCredentialId) {
    throw new Error('Brak klucza. Najpierw wykonaj registerWebAuthnTest()');
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const allowCredentials: PublicKeyCredentialDescriptor[] = [
    {
      type: 'public-key',
      id: base64urlToUint8Array(storedCredentialId) as BufferSource,
      transports: ['usb', 'nfc', 'ble', 'internal', 'hybrid'],
    },
  ];
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge,
    rpId: window.location.hostname,
    allowCredentials,
    userVerification: 'preferred',
    timeout: 60_000,
  };

  try {
    const credential = (await navigator.credentials.get({
      publicKey,
    })) as PublicKeyCredential;
    if (!credential) throw new Error('Logowanie przerwane');
    const response = credential.response as AuthenticatorAssertionResponse;
    console.log(`Logowanie WebAuthn dla {credential.id}!`);
    console.log('Signature (base64url):', uint8ArrayToBase64url(response.signature));
    console.log('ClientDataJSON:', new TextDecoder().decode(response.clientDataJSON));

  } catch (err: any) {
    if (err.name === 'NotAllowedError') {
      console.warn('Użytkownik anulował lub klucz nie jest dostępny');
    } else {
      console.error('Błąd logowania:', err);
    }
    throw err;
  }
}