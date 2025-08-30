#!/usr/bin/env python
# coding: utf-8

import argparse
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
import uuid as uuidmod
from auth.context.database import DataManager
from conf import SQLALCHEMY_DATABASE_URL


# Asynchroniczna konfiguracja bazy danych
#SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("sqlite:///", "sqlite+aiosqlite:///")
engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False)

async def create():
    async with AsyncSessionLocal() as session:
        dm = DataManager(session)
        await dm.create()

async def demo():

    async with AsyncSessionLocal() as session:
        dm = DataManager(session)
        address_id = await dm.add_address(country='Poland')
        await dm.add_user('demo', 'demo', name='John Down', email='jd@example.com')
        #, address_id=address_id)
        await dm.add_client(ident='demoapp', secret='secret', system_user_id=1, auth_redirect_uri='http://127.0.0.1:3000')

async def test():

    async with AsyncSessionLocal() as session:
        dm = DataManager(session)
        user_id = await dm.check_user('demo', 'demo')
        client = await dm.get_client(1)
        print(f"User ID: {user_id}")
        print(f"Client: {client}")

async def uuid(id: int):

    async with AsyncSessionLocal() as session:
        dm = DataManager(session)
        client = await dm.get_client(id)
        if client:
            print(client.uuid)
        else:
            print("Not found")

async def user(ident: str, secret: str, email: str):

    async with AsyncSessionLocal() as session:
        dm = DataManager(session)
        user_id = await dm.add_user(ident, secret, email=email)
        print(f"User {ident} added with ID {user_id}")

async def client(ident: str, secret: str, uri: str, user_id: int = 1):

    async with AsyncSessionLocal() as session:
        dm = DataManager(session)
        client_id = await dm.add_client(ident, secret, user_id, uri)
        print(f"Client {ident} added with ID {client_id}")

if __name__ == "__main__":
    import asyncio
    parser = argparse.ArgumentParser(description='API Manager.', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('operation', help='''Operation:
       create - create database schema
       demo - insert demo data to database
       test - select demo data
       user - register user
       client - register client
       uuid - client_id to uuid
    ''')
    parser.add_argument('--ident', help='login/identifier for new object')
    parser.add_argument('--secret', help='Secret/Password for new object')
    parser.add_argument('--uri', help='Redirect URI')
    parser.add_argument('--email', help='Option: user email', default='')
    parser.add_argument('--id', help='Option: id (client\'s)', default='1')
#    parser.add_argument('--db', help='Database Path eg: sqlite:///demo.db')

    args = parser.parse_args()

    if not hasattr(args, 'operation'):
        parser.print_help()
    else:
#        if args.db:
#          SQLALCHEMY_DATABASE_URL
        if args.operation == 'create':
            asyncio.run(create())
        elif args.operation == 'demo':
            asyncio.run(demo())
        elif args.operation == 'uuid':
            asyncio.run(uuid(int(args.id)))
        elif args.operation == 'test':
            asyncio.run(test())
        elif args.operation in ('user', 'client'):
            if not args.ident or not args.secret:
                print('Mandatory parameters: ident, secret')
            else:
                if args.operation == 'user':
                    asyncio.run(user(args.ident, args.secret, args.email))
                else:
                    if not args.uri:
                        print('Mandatory parameter: uri')
                    else:
                        asyncio.run(client(args.ident, args.secret, args.uri, user_id=int(args.id)))
        else:
            parser.print_help()