from pykeepass import PyKeePass

kp = PyKeePass('db.kdbx', password='haslo')
for entry in kp.find_entries(title='https://www.example.com/login/'): #, first=True):
  print(entry.title)
  print(entry.username)
  print(entry.password)

