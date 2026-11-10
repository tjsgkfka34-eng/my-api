"""장바구니 API (FastAPI + Supabase).

보안 원칙
- Supabase secret 키는 서버 환경변수에만 존재하고 응답/로그에 절대 노출하지 않는다.
- CORS는 FRONT_ORIGINS 환경변수에 적은 주소만 허용한다 (와일드카드 금지).
- 장바구니는 "추측 불가능한 토큰"을 가진 사람만 접근한다 (DB에는 해시만 저장).
- 가격/합계는 항상 서버(DB) 값으로 계산한다. 클라이언트가 보낸 가격은 쓰지 않는다.
- DB 오류 내용은 클라이언트에 알려주지 않고 서버 로그에만 남긴다.
"""
import hashlib
import logging
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from supabase import create_client

load_dotenv()  # 로컬에선 .env, Railway에선 Variables가 이미 환경변수로 들어 있음

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("my-api")

# ------------------------------------------------------------------ 설정
IS_PROD = os.getenv("ENV", "development").lower() == "production"

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SECRET_KEY = os.environ["SUPABASE_SECRET_KEY"]


def parse_origins(raw: str) -> list[str]:
    origins = []
    for o in raw.split(","):
        o = o.strip().rstrip("/")
        if not o:
            continue
        if o == "*" or not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?", o):
            raise RuntimeError(f"FRONT_ORIGINS 형식 오류(와일드카드/경로 금지): {o!r}")
        origins.append(o)
    return origins


FRONT_ORIGINS = parse_origins(os.getenv("FRONT_ORIGINS", ""))
if IS_PROD and not FRONT_ORIGINS:
    # 운영에서 허용 주소가 비어 있으면 "전부 차단"이 안전하므로 실수를 바로 알리도록 중단
    raise RuntimeError("운영(ENV=production)에서는 FRONT_ORIGINS를 반드시 설정해야 합니다.")

MAX_QTY = 99
MAX_DISTINCT_ITEMS = 30
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MIN", "120"))   # IP당 분당 요청 수
CART_CREATE_LIMIT = int(os.getenv("CART_CREATE_PER_HOUR", "20"))  # IP당 시간당 장바구니 생성 수

sb = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)

app = FastAPI(
    title="my-api",
    # 운영에서는 API 문서를 공개하지 않는다
    docs_url=None if IS_PROD else "/docs",
    redoc_url=None,
    openapi_url=None if IS_PROD else "/openapi.json",
)

# ------------------------------------------------------------------ 미들웨어
_hits: dict[str, deque] = defaultdict(deque)


def client_ip(request: Request) -> str:
    if IS_PROD:
        # Railway 프록시가 덧붙이는 "맨 오른쪽" 값만 신뢰 (왼쪽은 클라이언트가 위조 가능)
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def too_many(key: str, limit: int, window: int) -> bool:
    now = time.monotonic()
    q = _hits[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    if len(_hits) > 20000:  # 메모리 보호: 오래된 키 정리
        for k in [k for k, v in _hits.items() if not v or now - v[-1] > window]:
            _hits.pop(k, None)
    return False


@app.middleware("http")
async def guard(request: Request, call_next):
    # 1) 요청 본문 크기 제한
    try:
        if int(request.headers.get("content-length", "0")) > 2048:
            return JSONResponse({"detail": "요청이 너무 큽니다."}, status_code=413)
    except ValueError:
        return JSONResponse({"detail": "잘못된 요청입니다."}, status_code=400)

    # 2) 속도 제한 (헬스체크와 CORS 사전요청은 제외)
    if request.url.path != "/health" and request.method != "OPTIONS":
        ip = client_ip(request)
        if too_many(f"all:{ip}", RATE_LIMIT, 60):
            return JSONResponse({"detail": "요청이 너무 많습니다. 잠시 후 다시 시도하세요."},
                                status_code=429, headers={"Retry-After": "60"})
        if request.method == "POST" and request.url.path == "/carts":
            if too_many(f"mk:{ip}", CART_CREATE_LIMIT, 3600):
                return JSONResponse({"detail": "요청이 너무 많습니다."}, status_code=429)

    response = await call_next(request)

    # 3) 보안 헤더
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    if IS_PROD:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# CORS는 가장 바깥(마지막에 추가)에 두어야 429 같은 오류 응답에도 CORS 헤더가 붙는다
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONT_ORIGINS,          # 허용 목록 외 사이트의 브라우저 요청은 차단
    allow_credentials=False,              # 쿠키를 쓰지 않으므로 끈다
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-Cart-Token"],
    max_age=600,
)


# ------------------------------------------------------------------ 공통 도우미
def db_fail(e: Exception):
    """DB 오류 상세는 로그에만 남기고 클라이언트에는 일반 메시지만 준다."""
    log.error("supabase error: %s", type(e).__name__, exc_info=IS_PROD is False)
    raise HTTPException(status_code=502, detail="일시적인 서버 오류입니다.")


TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{43}")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def current_cart_id(x_cart_token: str = Header(default="")) -> str:
    if not TOKEN_RE.fullmatch(x_cart_token):
        raise HTTPException(status_code=401, detail="장바구니 인증이 필요합니다.")
    try:
        rows = (
            sb.table("carts").select("id")
            .eq("token_hash", hash_token(x_cart_token)).limit(1).execute().data
        )
    except Exception as e:
        db_fail(e)
    if not rows:
        raise HTTPException(status_code=401, detail="장바구니 인증이 필요합니다.")
    return rows[0]["id"]


def cart_view(cart_id: str) -> dict:
    try:
        rows = (
            sb.table("cart_items")
            .select("product_id, quantity, products(name, price, emoji)")
            .eq("cart_id", cart_id).order("updated_at").execute().data
        )
    except Exception as e:
        db_fail(e)
    items, total, count = [], 0, 0
    for r in rows:
        p = r["products"]
        sub = p["price"] * r["quantity"]
        total += sub
        count += r["quantity"]
        items.append({
            "product_id": r["product_id"], "name": p["name"], "emoji": p["emoji"],
            "price": p["price"], "quantity": r["quantity"], "subtotal": sub,
        })
    return {"items": items, "total": total, "count": count}


# ------------------------------------------------------------------ 입력 모델
class AddItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    product_id: int = Field(gt=0, lt=2**31)
    quantity: int = Field(default=1, ge=1, le=MAX_QTY)


class SetQty(BaseModel):
    model_config = ConfigDict(extra="forbid")
    quantity: int = Field(ge=1, le=MAX_QTY)


ProductId = Path(gt=0, lt=2**31)


# ------------------------------------------------------------------ 라우트
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/products")
def products():
    try:
        return (
            sb.table("products")
            .select("id, name, description, price, emoji")
            .eq("active", True).order("id").execute().data
        )
    except Exception as e:
        db_fail(e)


@app.post("/carts", status_code=201)
def create_cart():
    """새 장바구니를 만들고 토큰을 '한 번만' 돌려준다. DB에는 해시만 저장한다."""
    token = secrets.token_urlsafe(32)  # 43자, 256비트 무작위
    try:
        sb.table("carts").insert({"token_hash": hash_token(token)}).execute()
    except Exception as e:
        db_fail(e)
    return {"token": token}


@app.get("/cart")
def get_cart(cart_id: str = Depends(current_cart_id)):
    return cart_view(cart_id)


@app.post("/cart/items")
def add_item(body: AddItem, cart_id: str = Depends(current_cart_id)):
    try:
        prod = (
            sb.table("products").select("id")
            .eq("id", body.product_id).eq("active", True).limit(1).execute().data
        )
        if not prod:
            raise HTTPException(status_code=404, detail="상품을 찾을 수 없습니다.")
        existing = (
            sb.table("cart_items").select("product_id, quantity")
            .eq("cart_id", cart_id).execute().data
        )
    except HTTPException:
        raise
    except Exception as e:
        db_fail(e)

    current = {r["product_id"]: r["quantity"] for r in existing}
    if body.product_id not in current and len(current) >= MAX_DISTINCT_ITEMS:
        raise HTTPException(status_code=400, detail="장바구니에 담을 수 있는 상품 수를 초과했습니다.")
    qty = min(current.get(body.product_id, 0) + body.quantity, MAX_QTY)
    try:
        sb.table("cart_items").upsert(
            {"cart_id": cart_id, "product_id": body.product_id, "quantity": qty,
             "updated_at": now_iso()},
            on_conflict="cart_id,product_id",
        ).execute()
    except Exception as e:
        db_fail(e)
    return cart_view(cart_id)


@app.patch("/cart/items/{product_id}")
def set_quantity(body: SetQty, product_id: int = ProductId,
                 cart_id: str = Depends(current_cart_id)):
    try:
        res = (
            sb.table("cart_items").update({"quantity": body.quantity, "updated_at": now_iso()})
            .eq("cart_id", cart_id).eq("product_id", product_id).execute()
        )
    except Exception as e:
        db_fail(e)
    if not res.data:
        raise HTTPException(status_code=404, detail="장바구니에 없는 상품입니다.")
    return cart_view(cart_id)


@app.delete("/cart/items/{product_id}")
def remove_item(product_id: int = ProductId, cart_id: str = Depends(current_cart_id)):
    try:
        sb.table("cart_items").delete().eq("cart_id", cart_id).eq("product_id", product_id).execute()
    except Exception as e:
        db_fail(e)
    return cart_view(cart_id)


@app.delete("/cart")
def clear_cart(cart_id: str = Depends(current_cart_id)):
    try:
        sb.table("cart_items").delete().eq("cart_id", cart_id).execute()
    except Exception as e:
        db_fail(e)
    return cart_view(cart_id)
