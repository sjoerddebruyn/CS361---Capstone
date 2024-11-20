import os
import io
import base64
from fastapi import FastAPI, Request, Form, UploadFile, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from utils.id_gen import id_gen
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import socket
import json
from starlette.middleware.sessions import SessionMiddleware

# Load environment variables from the .env file
load_dotenv()

# MongoDB URI and database setup
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URI is not set in the environment variables.")
MONGO_DB_NAME = MONGO_URI.split("/")[-1].split("?")[0]
if not MONGO_DB_NAME:
    raise ValueError("MONGO_URI does not include a valid database name.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.mongodb_client = AsyncIOMotorClient(MONGO_URI)
    app.mongodb = app.mongodb_client[MONGO_DB_NAME]
    yield
    app.mongodb_client.close()

# Initialize FastAPI app with MongoDB connection
app = FastAPI(lifespan=lifespan)

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key="your_secret_key_here")

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Utility function for current user
def get_current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="User not authenticated.")
    return user_id

# User registration model
class User(BaseModel):
    username: str
    email: str
    password: str
    id: str

# Routes

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
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = await app.mongodb["users"].find_one({"username": username})
    if user and user["password"] == password:
        request.session["user_id"] = user["id"]  # Start session
        
        return RedirectResponse(url="/encrypt.html", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Incorrect username or password"})

@app.post("/logout")
async def logout(request: Request):
    request.session.clear()  # Clear session
    return RedirectResponse(url="/loggedOut.html", status_code=302)

@app.get("/register.html", response_class=HTMLResponse)
async def show_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register.html", response_class=HTMLResponse)
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    if password != confirm_password:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Passwords do not match."})
    
    # Check if the username already exists
    existing_user = await app.mongodb["users"].find_one({"username": username})
    if existing_user:
        return templates.TemplateResponse(
            "register.html", 
            {"request": request, "error": "Username already taken. Please choose a different one."}
        )
    
    # Proceed with registration if the username is available
    user_id = id_gen()
    await app.mongodb["users"].insert_one({
        "username": username,
        "email": email,
        "password": password,
        "id": user_id
    })
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
async def show_encrypt(request: Request):
    return templates.TemplateResponse("encrypt.html", {"request": request})

@app.post("/encrypt", response_class=JSONResponse)
async def encrypt(
    request: Request,
    file: UploadFile = None,
    algorithm: str = Form(...),
    password: str = Form(...),
):
    user_id = get_current_user(request)  # Ensure user is authenticated
    if not file:
        return JSONResponse({"error": "No file provided."}, status_code=400)

    # Read the file content and metadata
    file_content = (await file.read()).decode("utf-8")
    file_name = file.filename

    # Communicate with the key generation microservice
    HOST, KEYPORT, ENCRYPTPORT = "127.0.0.1", 65432, 65433

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((HOST, KEYPORT))
            request_data = json.dumps({
                "user_id": user_id,
                "file_name": file_name,
                "algorithm": algorithm,
                "file_content": file_content,
                "password": password
            })
            client.sendall(request_data.encode())
            response_data = client.recv(1024).decode()
            response = json.loads(response_data)

            # extract key (potentially seed and salt as well) from keygen response
            key = response.get("key")
            iv = response.get("iv")

            # Handle errors from the encryption service
            if "error" in response:
                return JSONResponse({"error": response["error"]}, status_code=500)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    
    try:
        # some issue with encryption that must be handled
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:   
            client.connect((HOST, ENCRYPTPORT))
            request_data = json.dumps({
                "service_type": "e",
                "file_name": file_name,
                "file_content": file_content,
                "key": key,
                "iv": iv,
                "algorithm": algorithm
            })
            client.sendall(request_data.encode())
            response_data = client.recv(1024).decode()
            response = json.loads(response_data)
 
            if "error" in response:
                return JSONResponse({"error": response["error"]}, status_code=500)
    except Exception as e:
        return JSONResponse({"error, issue with e": str(e)}, status_code=500)

    
    return RedirectResponse(url="/encryptSuccess.html", status_code=302)

@app.get("/encryptInfo.html", response_class=HTMLResponse)
async def read_encryptInfo(request: Request):
    return templates.TemplateResponse("encryptInfo.html", {"request": request})

@app.get("/loggedOut.html", response_class=HTMLResponse)
async def read_loggedOut(request: Request):
    return templates.TemplateResponse("loggedOut.html", {"request": request})

@app.get("/encryptSuccess.html", response_class=HTMLResponse)
async def read_encrypt_success(request: Request):
    return templates.TemplateResponse("encryptSuccess.html", {"request": request})
