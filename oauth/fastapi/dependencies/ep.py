# endpoint:
# - log

from fastapi import Request
from configparser import ConfigParser

import logging

debug=True

async def log(request: Request):
  logger = logging.getLogger("collector")
  logger.info(f"{request.method} {request.url}")
  if debug and request:
    try:
      body = request.body() #await request.body()
      logger.debug("Body: %s" % body)
      logger.debug("Headers:")
      for name, value in request.headers.items():
        logger.debug(f"\t{name}: {value}")
    except Exception as e:
      logger.debug(e)
  return logger


from conf.init import config

def conf() -> ConfigParser:
  return config