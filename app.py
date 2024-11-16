import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from utils.id_gen import id_gen
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# Get the MongoDB URI from environment variables
MONGO_URI = os.getenv("MONGO_URI")

# Check if the URI contains a database name
if MONGO_URI is None or '/' not in MONGO_URI:
    raise ValueError("MongoDB URI must contain a database name.")

# Extract the database name from the URI
MONGO_DB_NAME = MONGO_URI.split('/')[-1].split('?')[0]

# Check if the database name is empty
if not MONGO_DB_NAME:
    raise ValueError("MongoDB URI does not contain a valid database name.")

# MongoDB connection setup using lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # MongoDB client connection using the provided URI
    app.mongodb_client = AsyncIOMotorClient(MONGO_URI)
    
    # Explicitly select the database
    app.mongodb = app.mongodb_client[MONGO_DB_NAME]
    
    yield
    # Clean up MongoDB client on shutdown
    app.mongodb_client.close()

# Initialize the FastAPI app with the lifespan context manager
app = FastAPI(lifespan=lifespan)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Template setup
templates = Jinja2Templates(directory="templates")

# Pydantic model for user registration
class User(BaseModel):
    username: str
    email: str
    password: str
    id: str

# Routes for handling user actions

@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/home.html", response_class=HTMLResponse)
async def read_home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/login.html", response_class=HTMLResponse)
async def show_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login.html", response_class=HTMLResponse)
async def read_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user_found = False

    # Find the user in MongoDB
    user = await app.mongodb["users"].find_one({"username": username})
    if user:
        if user["password"] == password:
            return RedirectResponse(url="/selection.html", status_code=302)

    return templates.TemplateResponse("login.html", {"request": request, "error": "Incorrect username or password"})

@app.get("/register.html", response_class=HTMLResponse)
async def show_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register.html", response_class=HTMLResponse)
async def read_register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    if password != confirm_password:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Passwords do not match", "username": username, "email": email})

    # Generate ID and insert the user into MongoDB
    id = id_gen()  # Generate unique ID

    user = {
        "username": username,
        "email": email,
        "password": password,
        "id": id
    }

    # Insert user into MongoDB
    await app.mongodb["users"].insert_one(user)

    return RedirectResponse(url="/login.html", status_code=302)

@app.get("/selection.html", response_class=HTMLResponse)
async def read_selection(request: Request):
    return templates.TemplateResponse("selection.html", {"request": request})

@app.get("/emailCon.html", response_class=HTMLResponse)
async def read_emailCon(request: Request):
    return templates.TemplateResponse("emailCon.html", {"request": request})

@app.get("/forgotPassword.html", response_class=HTMLResponse)
async def read_forgotPassword(request: Request):
    return templates.TemplateResponse("forgotPassword.html", {"request": request})

@app.get("/decrypt.html", response_class=HTMLResponse)
async def read_decrypt(request: Request):
    return templates.TemplateResponse("decrypt.html", {"request": request})

@app.get("/decryptInfo.html", response_class=HTMLResponse)
async def read_decryptInfo(request: Request):
    return templates.TemplateResponse("decryptInfo.html", {"request": request})

@app.get("/encrypt.html", response_class=HTMLResponse)
async def read_encrypt(request: Request):
    return templates.TemplateResponse("encrypt.html", {"request": request})

@app.get("/encryptInfo.html", response_class=HTMLResponse)
async def read_encryptInfo(request: Request):
    return templates.TemplateResponse("encryptInfo.html", {"request": request})

@app.get("/loggedOut.html", response_class=HTMLResponse)
async def read_loggedOut(request: Request):
    return templates.TemplateResponse("loggedOut.html", {"request": request})
