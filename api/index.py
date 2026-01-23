import os
from datetime import date, datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.garmin_auth import GarminAuthError, get_logged_in_client, resume_mfa_login, start_login
from src.token_store import issue_nonce


def _cors_config() -> tuple[list[str], bool]:
    raw = os.getenv("CORS_ALLOW_ORIGINS", "*")
    local = {
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://medoxie.com",
        "https://www.medoxie.com",
    }
    if raw.strip() == "*":
        # Avoid "*" + allow_credentials=True which yields no ACAO header.
        return sorted(local), True
    origins = {o.strip() for o in raw.split(",") if o.strip()}
    return sorted(origins | local), True


app = FastAPI(redirect_slashes=False)

# CORS: expose Mcp-Session-Id header for browser-based clients
_allow_origins, _allow_credentials = _cors_config()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Mcp-Session-Id"],
)

def _is_local_request(request: Request) -> bool:
    host = request.headers.get("host", "")
    return host.startswith("localhost") or host.startswith("127.0.0.1")


def _requires_https() -> bool:
    return os.getenv("REQUIRE_HTTPS", "1").strip() != "0"


@app.middleware("http")
async def enforce_https(request: Request, call_next):
    if _requires_https() and not _is_local_request(request):
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        if proto != "https":
            return JSONResponse({"error": "https_required"}, status_code=400)
    return await call_next(request)


@app.get("/")
def health():
    return {"ok": True}


@app.get("/auth/nonce")
async def auth_nonce(address: str):
    nonce = await issue_nonce(address)
    headers = {"Cache-Control": "no-store"}
    if not nonce:
        return JSONResponse({"error": "nonce_unavailable"}, status_code=500, headers=headers)
    return JSONResponse({"nonce": nonce}, headers=headers)


class AuthStartRequest(BaseModel):
    email: str
    password: str
    user_id: str


class AuthFinishRequest(BaseModel):
    user_id: str
    mfa_code: str
    mfa_token: str


def _parse_date(raw: str) -> date:
    try:
        return datetime.fromisoformat(raw).date()
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_date")


def _date_range(start: date, end: date) -> list[str]:
    if end < start:
        raise HTTPException(status_code=400, detail="invalid_date_range")
    days = (end - start).days
    return [(start + timedelta(days=offset)).isoformat() for offset in range(days + 1)]


@app.post("/auth/start")
async def auth_start(payload: AuthStartRequest):
    try:
        return await start_login(payload.user_id, payload.email, payload.password)
    except GarminAuthError as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=400)


@app.post("/auth/finish")
async def auth_finish(payload: AuthFinishRequest):
    try:
        await resume_mfa_login(payload.user_id, payload.mfa_token, payload.mfa_code)
        return {"status": "ok"}
    except GarminAuthError as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=400)


@app.get("/sleep")
async def sleep_data(
    user_id: str = Query(...),
    date_value: Optional[str] = Query(None, alias="date"),
    start_date: Optional[str] = Query(None, alias="startDate"),
    end_date: Optional[str] = Query(None, alias="endDate"),
):
    try:
        g, _ = await get_logged_in_client(user_id=user_id)
    except GarminAuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    if date_value:
        return g.get_sleep_data(date_value)
    if start_date or end_date:
        start = _parse_date(start_date or end_date)
        end = _parse_date(end_date or start_date)
    else:
        start = end = date.today()
    days = _date_range(start, end)
    return [{"date": day, "sleep": g.get_sleep_data(day)} for day in days]


@app.get("/activities")
async def activities(
    user_id: str = Query(...),
    limit: int = Query(20, ge=1, le=100),
    start_date: Optional[str] = Query(None, alias="startDate"),
    end_date: Optional[str] = Query(None, alias="endDate"),
):
    try:
        g, _ = await get_logged_in_client(user_id=user_id)
    except GarminAuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    if start_date or end_date:
        start = _parse_date(start_date or end_date)
        end = _parse_date(end_date or start_date)
    else:
        end = date.today()
        start = end - timedelta(days=14)
    acts = g.get_activities_by_date(start.isoformat(), end.isoformat())
    return acts[:limit]
