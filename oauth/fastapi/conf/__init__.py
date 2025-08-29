__version__ = "0.0.2"

from .init import config, Base, init_db, SQLALCHEMY_DATABASE_URL, get_db_session


try:
#    import flask
    flask=False
except ImportError:
    flask = None

if flask:
  from flask import Flask
  from .init import init_flask
  app = Flask(__name__,
              static_folder='../static',
              template_folder='../templates')
  init_flask(app,log=True)

