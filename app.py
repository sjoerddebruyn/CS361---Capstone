from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from utils.id_gen import id_gen
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()


app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

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
    password: str = Form(...)
    ):
    user_found = False

    try:
        with open("users.txt", "r") as file:
            for line in file:
                stored_id, stored_username, stored_email, stored_password = line.strip().split(", ")
                stored_username = stored_username.split(": ")[1]
                stored_password = stored_password.split(": ")[1]

                if stored_username == username:
                    user_found = True
                    if stored_password == password:

                        return RedirectResponse(url="/selection.html", status_code=302)
    except FileNotFoundError:
        return templates.TemplateResponse("login.html", {"request": request, "error": "No Registrations Found."})

    if not user_found:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Incorrect username or password"})
    
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
    confirm_password: str = Form(...)
    ):
    if password != confirm_password:
        return templates.TemplateResponse("register.html",{"request": request, "error": "passwords do not match", "username":username, "email":email})
    # current redirect goes to login, eventually will go through an email confirm first

    id = id_gen()
    with open('users.txt', 'a') as file:
        file.write(f"ID: {id}, Username: {username}, Email: {email}, Password: {password}\n")

    return RedirectResponse(url="/login.html", status_code=302)

@app.get("/selection.html", response_class=HTMLResponse)
async def read_selection(request: Request):
    return templates.TemplateResponse("selection.html", {"request": request})

@app.get("/emailCon.html", response_class=HTMLResponse)
async def read_eamilCon(request: Request):
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