import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import DateTime, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

ROOT = Path(__file__).parent
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./licenses.db")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
CRYPTO_PAY_TOKEN = os.getenv("CRYPTO_PAY_TOKEN", "")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
CRYPTO_WEBHOOK_SECRET = os.getenv("CRYPTO_WEBHOOK_SECRET", "")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
WEBAPP_URL = os.getenv("WEBAPP_URL", "")
DEV_TELEGRAM_ID = os.getenv("DEV_TELEGRAM_ID", "")

PLANS = {
    "week": {"name": "7 дней", "days": 7, "price": "3.00"},
    "month": {"name": "30 дней", "days": 30, "price": "8.00"},
    "quarter": {"name": "90 дней", "days": 90, "price": "20.00"},
    "forever": {"name": "Навсегда", "days": None, "price": "49.00"},
}

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})

class Base(DeclarativeBase):
    pass

class Order(Base):
    __tablename__ = "orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    telegram_id: Mapped[int] = mapped_column(index=True)
    plan: Mapped[str] = mapped_column(String(30))
    invoice_id: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    license_key: Mapped[str | None] = mapped_column(String(80), nullable=True, unique=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class TermsAcceptance(Base):
    __tablename__ = "terms_acceptances"
    telegram_id: Mapped[int] = mapped_column(primary_key=True)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)
app = FastAPI(title="License mini app")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

class Checkout(BaseModel):
    plan: str

class KeyActivation(BaseModel):
    key: str

def telegram_user(init_data: str | None) -> int:
    if not init_data:
        if DEV_TELEGRAM_ID:
            return int(DEV_TELEGRAM_ID)
        raise HTTPException(401, "Откройте приложение через Telegram.")
    if not BOT_TOKEN:
        raise HTTPException(503, "BOT_TOKEN не настроен.")
    values = dict(parse_qsl(init_data, keep_blank_values=True))
    signature = values.pop("hash", "")
    check_string = "\n".join(f"{key}={values[key]}" for key in sorted(values))
    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    expected = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    if not signature or not hmac.compare_digest(signature, expected):
        raise HTTPException(401, "Недействительные данные Telegram.")
    try:
        return int(json.loads(values["user"])["id"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(401, "Не найден пользователь Telegram.")

async def crypto(method: str, payload: dict) -> dict:
    if not CRYPTO_PAY_TOKEN:
        raise HTTPException(503, "CRYPTO_PAY_TOKEN не настроен.")
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            f"https://pay.crypt.bot/api/{method}", json=payload,
            headers={"Crypto-Pay-API-Token": CRYPTO_PAY_TOKEN},
        )
    data = response.json()
    if not response.is_success or not data.get("ok"):
        raise HTTPException(502, "Не удалось создать или проверить счёт Crypto Pay.")
    return data["result"]

def key() -> str:
    return "LIC-" + base64.b32encode(secrets.token_bytes(12)).decode().rstrip("=")

async def send_key(telegram_id: int, license_key: str, expires_at: datetime | None):
    if not BOT_TOKEN:
        return
    until = "бессрочно" if expires_at is None else expires_at.strftime("%d.%m.%Y")
    text = f"✅ Оплата получена!\n\nВаш ключ: <code>{license_key}</code>\nДействует: {until}"
    async with httpx.AsyncClient(timeout=15) as client:
        await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json={"chat_id": telegram_id, "text": text, "parse_mode": "HTML"})

def accepted(telegram_id: int) -> bool:
    with Session(engine) as db:
        return db.get(TermsAcceptance, telegram_id) is not None

def require_terms(telegram_id: int):
    if not accepted(telegram_id):
        raise HTTPException(403, "Сначала примите пользовательское соглашение.")

async def activate(invoice_id: str) -> Order | None:
    invoice = await crypto("getInvoices", {"invoice_ids": invoice_id})
    items = invoice.get("items", [])
    if not items or items[0].get("status") != "paid":
        return None
    with Session(engine) as db:
        order = db.scalar(select(Order).where(Order.invoice_id == invoice_id))
        if not order:
            return None
        if order.status == "paid":
            return order
        plan = PLANS[order.plan]
        order.status = "paid"
        order.license_key = key()
        order.expires_at = None if plan["days"] is None else datetime.now(timezone.utc) + timedelta(days=plan["days"])
        db.commit()
        db.refresh(order)
    await send_key(order.telegram_id, order.license_key, order.expires_at)
    return order

@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")

@app.get("/api/plans")
def plans():
    return [{"id": ident, **plan, "currency": "USDT"} for ident, plan in PLANS.items()]

@app.get("/api/me")
def me(x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    with Session(engine) as db:
        orders = db.scalars(select(Order).where(Order.telegram_id == telegram_id, Order.status == "paid").order_by(Order.created_at.desc())).all()
        latest = orders[0] if orders else None
        return {
            "telegram_id": telegram_id,
            "terms_accepted": db.get(TermsAcceptance, telegram_id) is not None,
            "license_key": latest.license_key if latest else None,
            "expires_at": latest.expires_at if latest else None,
            "purchases": len(orders),
        }

@app.post("/api/terms/accept")
def accept_terms(x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    with Session(engine) as db:
        if not db.get(TermsAcceptance, telegram_id):
            db.add(TermsAcceptance(telegram_id=telegram_id))
            db.commit()
    return {"ok": True}

@app.post("/api/keys/activate")
def activate_key(body: KeyActivation, x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    require_terms(telegram_id)
    supplied = body.key.strip().upper()
    with Session(engine) as db:
        order = db.scalar(select(Order).where(Order.license_key == supplied, Order.status == "paid"))
        if not order:
            raise HTTPException(404, "Ключ не найден или ещё не оплачен.")
        # A key is intentionally transferable: its holder may activate it for their own profile.
        order.telegram_id = telegram_id
        db.commit()
        return {"key": order.license_key, "expires_at": order.expires_at}

@app.post("/api/checkout")
async def checkout(body: Checkout, x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    require_terms(telegram_id)
    if body.plan not in PLANS:
        raise HTTPException(422, "Неизвестный тариф.")
    plan = PLANS[body.plan]
    invoice = await crypto("createInvoice", {
        "asset": "USDT", "amount": plan["price"], "description": f"Лицензия: {plan['name']}",
        "payload": json.dumps({"telegram_id": telegram_id, "plan": body.plan}),
        **({"paid_btn_name": "openBot", "paid_btn_url": WEBHOOK_URL} if WEBHOOK_URL else {}),
    })
    with Session(engine) as db:
        db.add(Order(telegram_id=telegram_id, plan=body.plan, invoice_id=str(invoice["invoice_id"])))
        db.commit()
    pay_url = invoice.get("mini_app_invoice_url") or invoice.get("bot_invoice_url") or invoice.get("pay_url")
    if not pay_url:
        raise HTTPException(502, "Crypto Pay не вернул ссылку на счёт.")
    return {"invoice_id": str(invoice["invoice_id"]), "pay_url": pay_url}

@app.get("/api/orders/{invoice_id}")
async def order_status(invoice_id: str, x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    with Session(engine) as db:
        order = db.scalar(select(Order).where(Order.invoice_id == invoice_id, Order.telegram_id == telegram_id))
        if not order:
            raise HTTPException(404, "Счёт не найден.")
    activated = await activate(invoice_id)
    if activated:
        return {"status": "paid", "key": activated.license_key, "expires_at": activated.expires_at}
    return {"status": "pending"}

@app.post("/api/crypto/webhook/{secret}")
async def crypto_webhook(secret: str, request: Request):
    # Crypto Pay webhook contains an update object; the API is still re-checked in activate().
    if not CRYPTO_WEBHOOK_SECRET or not hmac.compare_digest(secret, CRYPTO_WEBHOOK_SECRET):
        raise HTTPException(404, "Не найдено")
    data = await request.json()
    update = data.get("payload", data)
    if update.get("update_type") == "invoice_paid":
        invoice_id = str(update.get("payload", {}).get("invoice_id", ""))
        if invoice_id:
            await activate(invoice_id)
    return {"ok": True}

@app.post("/api/telegram/webhook/{secret}")
async def telegram_webhook(secret: str, request: Request, x_telegram_bot_api_secret_token: str | None = Header(default=None)):
    """Receives /start and returns an inline Web App button; configured in Telegram setWebhook."""
    if (not TELEGRAM_WEBHOOK_SECRET or not hmac.compare_digest(secret, TELEGRAM_WEBHOOK_SECRET)
            or not x_telegram_bot_api_secret_token or not hmac.compare_digest(x_telegram_bot_api_secret_token, TELEGRAM_WEBHOOK_SECRET)):
        raise HTTPException(404, "Не найдено")
    update = await request.json()
    message = update.get("message", {})
    if not message.get("text", "").startswith("/start") or not WEBAPP_URL or not BOT_TOKEN:
        return {"ok": True}
    chat_id = message.get("chat", {}).get("id")
    if not chat_id:
        return {"ok": True}
    text = ("👋 <b>Добро пожаловать!</b>\n\n"
            "Здесь можно ознакомиться с сервисом, принять соглашение и выбрать лицензию. "
            "Нажмите кнопку ниже, чтобы открыть приложение.")
    keyboard = {"inline_keyboard": [[{"text": "🚀 Запустить", "web_app": {"url": WEBAPP_URL}}]]}
    async with httpx.AsyncClient(timeout=15) as client:
        await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json={"chat_id": chat_id, "text": text, "parse_mode": "HTML", "reply_markup": keyboard})
    return {"ok": True}
