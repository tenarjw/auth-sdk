import numpy as np
from math import gcd
from random import randint
from primesieve import primes
from sympy import primerange
# SymPy bez problemu obsłuży bardzo duże liczby z którymi primesieve sobie nie radzi
# pip  install sympy

MAX_C_VALUE = 2**64 - 1

def generate_prime(min_val, max_val):
  """Generuje losową liczbę pierwszą z zakresu [min_val, max_val]."""
  if max_val<MAX_C_VALUE:
    prime_list = primes(min_val, max_val)
    if not prime_list:
      raise ValueError("Brak liczb pierwszych w podanym zakresie.")
    return prime_list[randint(0, len(prime_list)-1)]
  else:
    prime_generator = primerange(min_val, max_val)
    # Wynikiem jest generator, który można przekonwertować na listę
    # ale to trwa bardzo długo
    rindex = randint(0, randint(0, 10000))
    pselected=0
    count=0
    for prime in prime_generator:
      count += 1
      if (count==rindex) or (pselected==0):
        pselected=prime
        if count==rindex:
          break
    if pselected==0:
      raise ValueError("Brak liczb pierwszych w podanym zakresie.")
    return pselected




def extended_gcd(a, b):
  """Rozszerzony algorytm Euklidesa. Zwraca (gcd, x, y), gdzie a*x + b*y = gcd(a,b)."""
  if a == 0:
    return (b, 0, 1)
  g, y, x = extended_gcd(b % a, a)
  return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
  """Oblicza odwrotność modularną a modulo m."""
  g, x, _ = extended_gcd(a, m)
  if g != 1:
    raise ValueError("Odwrotność modularna nie istnieje.")
  return x % m

def generate_rsa_keys(bit_length=1024):
  """Generuje klucze RSA o podanej długości bitowej."""
  # W praktyce używa się kryptograficznie bezpiecznych generatorów (np. secrets).
  min_p = 2**(bit_length//2 - 1)
  max_p = 2**(bit_length//2)
  p = generate_prime(min_p, max_p)
  q = generate_prime(min_p, max_p)
  while q == p:  # Zapewnia, że p i q są różne
    q = generate_prime(min_p, max_p)

  n = p * q
  phi = (p - 1) * (q - 1)

  # Typowa wartość e (65537 to popularny wybór)
  e = 65537
  if gcd(e, phi) != 1:
    raise ValueError("Wybierz inne e.")

  d = mod_inverse(e, phi)
  return (e, n), (d, n)

def rsa_encrypt_decrypt(message, key, n):
  """Szyfruje/deszyfruje wiadomość za pomocą klucza RSA."""
  if message >= n:
    raise ValueError("Wiadomość musi być mniejsza od n.")
  return pow(message, key, n)

if __name__ == "__main__":
  # Przykład użycia
  public_key, private_key = generate_rsa_keys(bit_length=64)  # Mniejsza długość dla demonstracji
  print(f"Klucz publiczny (e, n): {public_key}")
  print(f"Klucz prywatny (d, n): {private_key}")

  # Test szyfrowania
  M = 123  # Wiadomość do zaszyfrowania
  C = rsa_encrypt_decrypt(M, public_key[0], public_key[1])
  M_decrypted = rsa_encrypt_decrypt(C, private_key[0], private_key[1])

  print(f"Wiadomość: {M}")
  print(f"Zaszyfrowana: {C}")
  print(f"Odszyfrowana: {M_decrypted}")
