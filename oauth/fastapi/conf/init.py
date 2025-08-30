import configparser
import logging
import os
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

config = configparser.ConfigParser()
config.read("conf/api.ini")

from pathlib import Path

basedir = Path(os.path.abspath(os.path.dirname(__file__))).parent.absolute()
db_name = config['db']['name']
#SQLALCHEMY_DATABASE_URL = 'sqlite:///' + os.path.join(basedir, db_name + '.db')

#SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///" + os.path.join(basedir, db_name + '.db')
SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///test.db"
config['db']['uri']=SQLALCHEMY_DATABASE_URL

Base = None

def init_db(Base):
  if Base:
    return Base
  else:
    return declarative_base()


def get_db_session(bind=True, debug=False, create=False):
  global Base
  Base=init_db(Base)
  engine = create_engine(SQLALCHEMY_DATABASE_URL, echo=debug)
  if bind or create:
    Base.metadata.bind = engine
  if create:
    try:
      Base.metadata.create_all(engine)
    except Exception as e:
      print('DB already exist ? [%s]' % e)
  return sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_logging(log=False):
  if log:
    logfile = config['app']['logfilename']
    logging.basicConfig(filename=logfile, level=logging.DEBUG, \
                        format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

