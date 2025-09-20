#!/usr/bin/env python
# coding: utf-8
"""
e-Doręczenia
"""
import argparse

from edr_connector import list_inbox, test_send, fetch_evidences

if __name__ == "__main__":
  test=False
  parser = argparse.ArgumentParser(description='e-Doręczenia')
  parser.add_argument('cmd', help='operacja: send inbox evidences')
  args = parser.parse_args()
  if args.cmd == 'inbox':
    list_inbox(test)
    exit(0)
  elif args.cmd == 'evidences':
    fetch_evidences(test)
    exit(0)
  elif args.cmd == 'send':
    print('send')
    test_send('AE:PL-xxxxxxxxxxxxxx','test','treść',
              'requirements.txt','requirements.txt')
    exit(0)
  parser.print_help()

