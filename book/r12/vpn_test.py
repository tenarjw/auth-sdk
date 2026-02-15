#!/usr/bin/env python3
import socket

senddata = b"\x38\x01\x00\x00\x00\x00\x00\x00\x00"

def checkserver(ip, port):
    print(f"Checking {ip}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.connect((ip, port))
    print("Sending request...")
    sock.send(senddata)
    try:
        dta = sock.recv(100)
        print(f"Server reply: {dta}")
    except:
        print("Server not responding")
    sock.close()

if __name__ == "__main__":
    checkserver("vpn.example.com", 1194)
