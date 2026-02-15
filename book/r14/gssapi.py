#!/usr/bin/env python3
import gssapi
import base64

krb5_mech = "1.2.840.113554.1.2.2"  # OID Kerberos V5
krb5_oid = gssapi.OID.from_str(krb5_mech)

targ_name = 'serwer.firma.pl'
target_name = gssapi.Name(f"host@{targ_name}", gssapi.NameType.hostbased_service)
print(f'nazwa_docelowa={target_name}')

ctx = gssapi.SecurityContext(
    name=target_name,
    mech=krb5_oid,
    flags=gssapi.RequirementFlag.protection_ready | gssapi.RequirementFlag.integrity | gssapi.RequirementFlag.delegate_to_peer
)

c_token = None
while not ctx.complete:
    c_token = ctx.step(c_token)
    if c_token is None:
        break

print(f'Typ tokenu: {type(c_token)}')
print(f'Token: {base64.b64encode(c_token).decode("ascii") if c_token else "Brak"}')

# Tworzenie kodu integralności wiadomości (MIC)
mic_msg = b"Wiadomość"
mic_token = ctx.get_mic(mic_msg)
print(f'Token MIC: {base64.b64encode(mic_token).decode("ascii")}')
