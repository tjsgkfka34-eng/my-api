import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

# 로컬에선 .env를 읽고, Railway에선 Variables가 이미 들어 있음
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SECRET_KEY = os.environ["SUPABASE_SECRET_KEY"]
FRONT_ORIGINS = [
    o.strip() for o in os.getenv("FRONT_ORIGINS", "").split(",") if o.strip()
]

sb = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)

app = FastAPI(title="my-api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONT_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class MessageIn(BaseModel):
    content: str


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/v")
def health2():
    return {"status": "안녕"}

@app.get("/db-check")
def db_check():
    """Supabase 연결 확인: messages 테이블을 1건 조회."""
    try:
        sb.table("messages").select("id").limit(1).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Supabase error: {e}")
    return {"supabase": "connected"}


@app.get("/messages")
def list_messages():
    try:
        res = (
            sb.table("messages")
            .select("*")
            .order("id", desc=True)
            .limit(50)
            .execute()
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Supabase error: {e}")
    return res.data


@app.post("/messages", status_code=201)
def create_message(body: MessageIn):
    content = body.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="content is empty")
    try:
        res = sb.table("messages").insert({"content": content}).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Supabase error: {e}")
    return res.data[0]
