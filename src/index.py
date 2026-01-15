import contextlib
import os
from datetime import date, timedelta
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from mcp.server.fastmcp import FastMCP

from .garmin_auth import GarminAuthError, get_logged_in_client, resume_mfa_login

# Stateless Streamable HTTP is recommended for scalable deployments
mcp = FastMCP(
    "Medoxie Garmin MCP",
    stateless_http=True,
    json_response=True,
    streamable_http_path="/",  # so mounting at /api/mcp gives endpoint exactly /api/mcp
)


def _parse_origins() -> list[str]:
    raw = os.getenv("CORS_ALLOW_ORIGINS", "*")
    return ["*"] if raw.strip() == "*" else [o.strip() for o in raw.split(",") if o.strip()]


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Needed to run the MCP session manager (even in stateless mode)
    async with mcp.session_manager.run():
        yield


app = FastAPI(lifespan=lifespan)

# CORS: expose Mcp-Session-Id header for browser-based clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=_parse_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Mcp-Session-Id"],
)

MCP_API_KEY = os.getenv("MCP_API_KEY")  # optional bearer token gate


@app.middleware("http")
async def mcp_auth_middleware(request: Request, call_next):
    if MCP_API_KEY and request.url.path.startswith("/api/mcp"):
        auth = request.headers.get("authorization", "")
        if auth != f"Bearer {MCP_API_KEY}":
            # keep it simple; MCP clients can send Authorization header
            return FastAPI.responses.JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)


@app.get("/")
def health():
    return {"ok": True, "mcp": "/api/mcp"}


# Mount MCP server at /api/mcp
app.mount("/api/mcp", mcp.streamable_http_app())


# -----------------------
# MCP Tools (Auth)
# -----------------------

@mcp.tool()
async def garmin_auth_start(user_id: str, email: str, password: str):
    """
    Starts Garmin auth. If MFA is enabled, returns MFA_REQUIRED with a token.
    Store tokens in Upstash/Vercel KV for future calls.
    """
    try:
        await get_logged_in_client(user_id=user_id, email=email, password=password)
        return {"status": "ok"}
    except GarminAuthError as e:
        msg = str(e)
        if msg.startswith("MFA_REQUIRED::"):
            return {"status": "needs_mfa", "mfa_token": msg.split("MFA_REQUIRED::", 1)[1]}
        return {"status": "error", "message": msg}


@mcp.tool()
async def garmin_auth_finish(user_id: str, email: str, password: str, mfa_token: str, mfa_code: str):
    """
    Completes MFA and stores tokens.
    """
    try:
        await resume_mfa_login(user_id, email, password, mfa_token, mfa_code)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# -----------------------
# MCP Tools (Data)
# -----------------------

@mcp.tool()
async def garmin_daily_summary(
    user_id: str,
    day: str,  # YYYY-MM-DD
    email: Optional[str] = None,
    password: Optional[str] = None,
):
    """
    Returns Garmin 'user summary' (steps, calories, distance, floors, etc.) for a day.
    """
    g, _ = await get_logged_in_client(user_id=user_id, email=email, password=password)
    return g.get_user_summary(day)


@mcp.tool()
async def garmin_sleep(
    user_id: str,
    day: str,  # YYYY-MM-DD
    email: Optional[str] = None,
    password: Optional[str] = None,
):
    """
    Returns Garmin sleep data for a day. (Method exists in python-garminconnect.)
    """
    g, _ = await get_logged_in_client(user_id=user_id, email=email, password=password)
    return g.get_sleep_data(day)


@mcp.tool()
async def garmin_recent_activities(
    user_id: str,
    days: int = 14,
    activity_type: Optional[str] = None,
    limit: int = 20,
    email: Optional[str] = None,
    password: Optional[str] = None,
):
    """
    Returns activities from (today - days) .. today using get_activities_by_date().
    """
    g, _ = await get_logged_in_client(user_id=user_id, email=email, password=password)
    end = date.today().isoformat()
    start = (date.today() - timedelta(days=days)).isoformat()
    acts = g.get_activities_by_date(start, end, activity_type)  # commonly used pattern
    return acts[: max(1, limit)]


@mcp.tool()
async def garmin_activity_details(
    user_id: str,
    activity_id: int,
    maxpoly: int = 0,
    email: Optional[str] = None,
    password: Optional[str] = None,
):
    """
    Detailed activity info for one activityId.
    """
    g, _ = await get_logged_in_client(user_id=user_id, email=email, password=password)
    # get_activity_details exists and is used in the library’s demo/pypi docs
    return g.get_activity_details(activity_id, maxpoly=maxpoly)