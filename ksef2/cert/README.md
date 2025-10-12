Kwalifikowana pieczęć firmowa powinna mieć w polu **Subject**:

| OID        | Nazwa                  | Przykład              |
| ---------- | ---------------------- | --------------------- |
| `2.5.4.10` | organizationName       | `Kowalski sp. z o.o.` |
| `2.5.4.97` | organizationIdentifier | `VATPL9217964649`     |
| `2.5.4.3`  | commonName             | `Kowalski sp. z o.o.` |
| `2.5.4.6`  | countryName            | `PL`                  |

Możesz to sprawdzić:

```bash
openssl x509 -in pieczec.pem -noout -subject -nameopt RFC2253
```
lub (dla pfx):
```bash
openssl pkcs12 -in $(pwd)/cert.pfx -nodes  | openssl x509 -noout -subject
```
Wynik powinien zawierać coś takiego:

```
subject=C=PL,O=Kowalski sp. z o.o.,2.5.4.97=VATPL-9217964649,CN=Kowalski sp. z o.o.
```


Zaufane CA:

[https://esignature.ec.europa.eu/efda/tl-browser/#/screen/home](https://esignature.ec.europa.eu/efda/tl-browser/#/screen/home)
