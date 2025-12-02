#!/usr/bin/env python3
# coding: utf-8
# authors: Jerzy Wawro
# (C) 2024/2025

from fastapi import FastAPI, APIRouter
from  .WK import router as router_wk


v2router = FastAPI()

api_description = """
API  wkdemo
"""

api_tags_metadata = [
    {
        "name": "e-talr",
        "description": "Operacje na walucie",
        "externalDocs": {
         "description": "zob. /v2/et/docs",
         "url": "https://api.wkdemo.com",
       },
    },

]

subapp_test = FastAPI(openapi_tags=api_tags_metadata,
                       description=api_description,
                       version="1.0.0",
                       terms_of_service="#",
                       license_info={
                         "name": "Apache 2.0",
                         "identifier": "MIT",
                       },
                       )
app_wk = FastAPI()
app_wk.include_router(router_wk)
v2router.mount("/et", app_wk)
