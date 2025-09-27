Ważne!!!

1)
Zegar – różnica >5 minut między serwerem a klientem powoduje błąd

2) 
System plików hosta (maszyny na której uruchamiasz kontener Docker) musi mieć atrybuty dostępu zgodne z Windows.
W przypadku Linix: acl+user_xattrr
Na przykłądzie Ubuntu:
```
sudo apt update
sudo apt install acl attr
```

W pliku /etc/fstab dopisujemy do wolumenu na którym będzie Docker: `,acl,user_xattr`

Na przykład:
```
UUID=xxxx-xxxx  /  ext4  defaults,acl,user_xattr  0 1
```

albo:
```
UUID=xxxx  /   ext4   errors=remount-ro,acl,user_xattr   0   1
```

Potem restart, albo remount - np.:

```
sudo mount -o remount,acl,user_xattr /
```



