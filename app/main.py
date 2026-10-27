import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from app.config import settings
from app.routers import recon, ai_copilot

app = FastAPI(
    title=settings.APP_NAME,
    description="Autonomous Attack Surface Intelligence & Tactical Recon Console",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(recon.router)
app.include_router(ai_copilot.router)

# Static Files Path (Supports both local FastAPI and Cloudflare Pages static hosting)
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
static_dir = os.path.join(current_dir, "static")

css_dir = os.path.join(root_dir, "css") if os.path.exists(os.path.join(root_dir, "css")) else os.path.join(static_dir, "css")
js_dir = os.path.join(root_dir, "js") if os.path.exists(os.path.join(root_dir, "js")) else os.path.join(static_dir, "js")

if os.path.exists(css_dir):
    app.mount("/css", StaticFiles(directory=css_dir), name="css")

if os.path.exists(js_dir):
    app.mount("/js", StaticFiles(directory=js_dir), name="js")

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/api/health")
def healthcheck():
    return {
        "status": "online",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }

@app.get("/")
def serve_dashboard():
    root_index = os.path.join(root_dir, "index.html")
    if os.path.exists(root_index):
        return FileResponse(root_index)
    static_index = os.path.join(static_dir, "index.html")
    if os.path.exists(static_index):
        return FileResponse(static_index)
    return {"message": f"{settings.APP_NAME} API is running. Visit /docs for OpenAPI specs."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
