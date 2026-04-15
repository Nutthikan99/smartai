from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "smartkey.db")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://innovetixai.com")
FRONTEND_PREVIEW_ORIGIN = os.getenv("FRONTEND_PREVIEW_ORIGIN", "https://smartkey.pages.dev")
PROMPTPAY_WEBHOOK_SECRET = os.getenv("PROMPTPAY_WEBHOOK_SECRET", "change-me")
DEFAULT_AMOUNT = int(os.getenv("DEFAULT_AMOUNT", "50"))
TRANSACTION_EXPIRE_MINUTES = int(os.getenv("TRANSACTION_EXPIRE_MINUTES", "15"))
PIN_EXPIRE_MINUTES = int(os.getenv("PIN_EXPIRE_MINUTES", "10"))
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_SUCCESS_URL = os.getenv("STRIPE_SUCCESS_URL", f"{FRONTEND_ORIGIN}/?payment=success")
STRIPE_CANCEL_URL = os.getenv("STRIPE_CANCEL_URL", f"{FRONTEND_ORIGIN}/?payment=cancel")

app = FastAPI(title="SmartKey API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, FRONTEND_PREVIEW_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id TEXT PRIMARY KEY,
                tag_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                amount INTEGER NOT NULL,
                status TEXT NOT NULL,
                qr_text TEXT,
                checkout_url TEXT,
                pin TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                pin_expires_at TEXT,
                paid_at TEXT,
                raw_provider_ref TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payment_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT,
                provider TEXT NOT NULL,
                event_type TEXT,
                payload_json TEXT,
                created_at TEXT NOT NULL
            )
            """
        )


@app.on_event("startup")
def startup_event() -> None:
    init_db()


class CreatePaymentSessionRequest(BaseModel):
    tag_id: str = Field(..., min_length=1, max_length=100)
    provider: Literal["promptpay", "stripe"] = "promptpay"
    amount: int = Field(DEFAULT_AMOUNT, ge=1, le=100000)


class CreatePaymentSessionResponse(BaseModel):
    success: bool
    transaction_id: str
    amount: int
    provider: str
    status: str
    qr_text: str
    checkout_url: Optional[str] = None


class PaymentStatusResponse(BaseModel):
    success: bool
    transaction_id: str
    status: Literal["PENDING", "PAID", "FAILED", "EXPIRED"]
    pin: Optional[str] = None
    paid_at: Optional[str] = None
    pin_expires_at: Optional[str] = None


def generate_transaction_id() -> str:
    ts = now_utc().strftime("%Y%m%d%H%M%S")
    return f"TX{ts}{secrets.token_hex(3).upper()}"


def generate_pin_4_digits() -> str:
    return f"{secrets.randbelow(10000):04d}"


def build_promptpay_qr_payload(transaction_id: str, amount: int, tag_id: str) -> str:
    # TODO: เปลี่ยนเป็น payload จริงจาก PSP/ธนาคารที่คุณเลือก
    return f"PROMPTPAY|TX={transaction_id}|AMOUNT={amount}|TAG={tag_id}"


def create_stripe_checkout_session(transaction_id: str, amount: int, tag_id: str) -> Optional[str]:
    if not STRIPE_SECRET_KEY:
        return None
    try:
        import stripe  # type: ignore
    except Exception:
        return None

    stripe.api_key = STRIPE_SECRET_KEY
    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{
            "price_data": {
                "currency": "thb",
                "product_data": {"name": f"SmartKey {tag_id}"},
                "unit_amount": amount * 100,
            },
            "quantity": 1,
        }],
        success_url=STRIPE_SUCCESS_URL,
        cancel_url=STRIPE_CANCEL_URL,
        metadata={"transaction_id": transaction_id, "tag_id": tag_id},
    )
    return getattr(session, "url", None)


def insert_transaction(transaction_id: str, tag_id: str, provider: str, amount: int, qr_text: str, checkout_url: Optional[str]) -> None:
    created_at = now_utc()
    expires_at = created_at + timedelta(minutes=TRANSACTION_EXPIRE_MINUTES)
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO transactions (
                transaction_id, tag_id, provider, amount, status, qr_text,
                checkout_url, created_at, expires_at
            ) VALUES (?, ?, ?, ?, 'PENDING', ?, ?, ?, ?)
            """,
            (transaction_id, tag_id, provider, amount, qr_text, checkout_url, iso(created_at), iso(expires_at)),
        )


def get_transaction(transaction_id: str) -> sqlite3.Row | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM transactions WHERE transaction_id = ?",
            (transaction_id,),
        ).fetchone()
        return row


def maybe_expire_transaction(transaction_id: str) -> sqlite3.Row:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM transactions WHERE transaction_id = ?", (transaction_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Transaction not found")
        if row["status"] == "PENDING" and now_utc() > datetime.fromisoformat(row["expires_at"]):
            conn.execute("UPDATE transactions SET status = 'EXPIRED' WHERE transaction_id = ?", (transaction_id,))
            row = conn.execute("SELECT * FROM transactions WHERE transaction_id = ?", (transaction_id,)).fetchone()
        return row


def log_event(provider: str, event_type: str, payload: dict, transaction_id: Optional[str] = None) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO payment_logs (transaction_id, provider, event_type, payload_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (transaction_id, provider, event_type, json.dumps(payload, ensure_ascii=False), iso(now_utc())),
        )


def mark_paid(transaction_id: str, provider_ref: Optional[str] = None) -> sqlite3.Row:
    existing = get_transaction(transaction_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if existing["status"] == "PAID":
        return existing

    paid_at = now_utc()
    pin = generate_pin_4_digits()
    pin_expires_at = paid_at + timedelta(minutes=PIN_EXPIRE_MINUTES)

    with get_db() as conn:
        conn.execute(
            """
            UPDATE transactions
            SET status = 'PAID', pin = ?, paid_at = ?, pin_expires_at = ?, raw_provider_ref = ?
            WHERE transaction_id = ?
            """,
            (pin, iso(paid_at), iso(pin_expires_at), provider_ref, transaction_id),
        )
        row = conn.execute("SELECT * FROM transactions WHERE transaction_id = ?", (transaction_id,)).fetchone()
        return row


def verify_hmac(raw_body: bytes, received_sig: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, received_sig or "")


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/api/create-payment-session", response_model=CreatePaymentSessionResponse)
def create_payment_session(payload: CreatePaymentSessionRequest) -> CreatePaymentSessionResponse:
    transaction_id = generate_transaction_id()

    if payload.provider == "promptpay":
        checkout_url = None
        qr_text = build_promptpay_qr_payload(transaction_id, payload.amount, payload.tag_id)
    else:
        checkout_url = create_stripe_checkout_session(transaction_id, payload.amount, payload.tag_id)
        qr_text = checkout_url or f"STRIPE|TX={transaction_id}|AMOUNT={payload.amount}|TAG={payload.tag_id}"

    insert_transaction(transaction_id, payload.tag_id, payload.provider, payload.amount, qr_text, checkout_url)

    return CreatePaymentSessionResponse(
        success=True,
        transaction_id=transaction_id,
        amount=payload.amount,
        provider=payload.provider,
        status="PENDING",
        qr_text=qr_text,
        checkout_url=checkout_url,
    )


@app.get("/api/payment-status/{transaction_id}", response_model=PaymentStatusResponse)
def payment_status(transaction_id: str) -> PaymentStatusResponse:
    row = maybe_expire_transaction(transaction_id)
    return PaymentStatusResponse(
        success=True,
        transaction_id=row["transaction_id"],
        status=row["status"],
        pin=row["pin"],
        paid_at=row["paid_at"],
        pin_expires_at=row["pin_expires_at"],
    )


@app.post("/api/mock-pay/{transaction_id}")
def mock_pay(transaction_id: str) -> dict:
    row = mark_paid(transaction_id, provider_ref="mock")
    return {
        "success": True,
        "transaction_id": row["transaction_id"],
        "status": row["status"],
        "pin": row["pin"],
    }


@app.post("/webhooks/promptpay")
async def promptpay_webhook(request: Request) -> dict:
    raw_body = await request.body()
    signature = request.headers.get("x-signature", "")
    if not verify_hmac(raw_body, signature, PROMPTPAY_WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = json.loads(raw_body.decode("utf-8"))
    transaction_id = payload.get("transaction_id")
    status = payload.get("status")
    provider_ref = payload.get("provider_ref")

    log_event("promptpay", payload.get("event_type", "payment.updated"), payload, transaction_id)

    if not transaction_id:
        raise HTTPException(status_code=400, detail="Missing transaction_id")

    if status == "PAID":
        row = mark_paid(transaction_id, provider_ref=provider_ref)
        return {"received": True, "transaction_id": row["transaction_id"], "pin": row["pin"]}

    return {"received": True}


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request) -> dict:
    raw_body = await request.body()
    payload = json.loads(raw_body.decode("utf-8"))
    log_event("stripe", payload.get("type", "unknown"), payload, None)

    # ถ้าคุณมี STRIPE_WEBHOOK_SECRET และ stripe package ติดตั้ง สามารถเปิด verify จริงได้ภายหลัง
    event_type = payload.get("type")
    data_object = payload.get("data", {}).get("object", {})
    metadata = data_object.get("metadata", {})
    transaction_id = metadata.get("transaction_id")
    provider_ref = data_object.get("id")

    if event_type in {"checkout.session.completed", "payment_intent.succeeded"} and transaction_id:
        row = mark_paid(transaction_id, provider_ref=provider_ref)
        return {"received": True, "transaction_id": row["transaction_id"], "pin": row["pin"]}

    return {"received": True}
