from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import FastAPI
from pydantic import BaseModel
import os

MONGODB_URL = os.getenv('MONGODB_URL', 'mongodb://localhost:') # <- Change this
DATABASE_NAME = 'db_name'

client = AsyncIOMotorClient(MONGODB_URL)
db = client[DATABASE_NAME]