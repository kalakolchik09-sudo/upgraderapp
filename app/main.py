import base64
import hashlib
import hmac
import json
import logging
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
from sqlalchemy import DateTime, Integer, String, create_engine, select, text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
ADMIN_TELEGRAM_ID = int(os.getenv("ADMIN_TELEGRAM_ID", "964442694"))

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

class ManualLicenseKey(Base):
    __tablename__ = "manual_license_keys"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    duration_days: Mapped[int] = mapped_column(Integer)
    used_by: Mapped[int | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class SupportTicket(Base):
    __tablename__ = "support_tickets"
    id: Mapped[int] = mapped_column(primary_key=True)
    telegram_id: Mapped[int] = mapped_column(index=True)
    message: Mapped[str] = mapped_column(String(2000))
    status: Mapped[str] = mapped_column(String(20), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class DemoRun(Base):
    __tablename__ = "demo_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    telegram_id: Mapped[int] = mapped_column(index=True)
    accounts: Mapped[str] = mapped_column(String(40))
    mode: Mapped[str] = mapped_column(String(12))
    interval_minutes: Mapped[int] = mapped_column(Integer)
    cycle: Mapped[int] = mapped_column(Integer, default=1)
    sent_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(12), default="active")
    telegram_message_id: Mapped[int | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class TermsAcceptance(Base):
    __tablename__ = "terms_acceptances"
    telegram_id: Mapped[int] = mapped_column(primary_key=True)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

# Create ORM tables and repair databases created by earlier application versions.
Base.metadata.create_all(engine)
with engine.begin() as connection:
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS terms_acceptances (
            telegram_id BIGINT PRIMARY KEY,
            accepted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """))
app = FastAPI(title="License mini app")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

class Checkout(BaseModel):
    plan: str

class KeyActivation(BaseModel):
    key: str

class ManualKeyCreate(BaseModel):
    duration_days: int

class SupportMessage(BaseModel):
    message: str

class SupportReply(BaseModel):
    message: str

class DemoRunStart(BaseModel):
    accounts: list[int]
    mode: str
    interval_minutes: int

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

def require_admin(telegram_id: int):
    if telegram_id != ADMIN_TELEGRAM_ID:
        raise HTTPException(403, "Раздел доступен только администратору.")

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
            "is_admin": telegram_id == ADMIN_TELEGRAM_ID,
        }

@app.post("/api/terms/accept")
def accept_terms(x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    with Session(engine) as db:
        if not db.get(TermsAcceptance, telegram_id):
            db.add(TermsAcceptance(telegram_id=telegram_id))
            db.commit()
    return {"ok": True}

@app.get("/api/admin/summary")
def admin_summary(x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    require_admin(telegram_id)
    with Session(engine) as db:
        orders = db.scalars(select(Order)).all()
        paid = [order for order in orders if order.status == "paid"]
        return {
            "orders_total": len(orders),
            "paid_total": len(paid),
            "users_total": len({order.telegram_id for order in orders}),
            "revenue_usdt": f"{sum(float(PLANS.get(order.plan, {}).get('price', 0)) for order in paid):.2f}",
        }

@app.post("/api/admin/keys")
def create_manual_key(body: ManualKeyCreate, x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    require_admin(telegram_id)
    if body.duration_days != -1 and body.duration_days < 1:
        raise HTTPException(422, "Укажите число дней или -1 для бессрочного ключа.")
    new_key = key()
    with Session(engine) as db:
        db.add(ManualLicenseKey(key=new_key, duration_days=body.duration_days))
        db.commit()
    return {"key": new_key, "duration_days": body.duration_days}

@app.get("/api/admin/users")
def admin_users(x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    require_admin(telegram_id)
    with Session(engine) as db:
        ids = {row[0] for row in db.execute(select(Order.telegram_id)).all()}
        ids.update(row[0] for row in db.execute(select(TermsAcceptance.telegram_id)).all())
        result = []
        for user_id in sorted(ids, reverse=True)[:100]:
            latest = db.scalar(select(Order).where(Order.telegram_id == user_id, Order.status == "paid").order_by(Order.created_at.desc()))
            result.append({"telegram_id": user_id, "license_key": latest.license_key if latest else None, "expires_at": latest.expires_at if latest else None})
    return result

@app.get("/api/admin/tickets")
def admin_tickets(x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    require_admin(telegram_id)
    with Session(engine) as db:
        tickets = db.scalars(select(SupportTicket).order_by(SupportTicket.created_at.desc()).limit(30)).all()
        return [{"id": ticket.id, "telegram_id": ticket.telegram_id, "message": ticket.message, "status": ticket.status, "created_at": ticket.created_at} for ticket in tickets]

@app.post("/api/support")
async def create_ticket(body: SupportMessage, x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    message = body.message.strip()
    if not message:
        raise HTTPException(422, "Напишите сообщение для поддержки.")
    with Session(engine) as db:
        ticket = SupportTicket(telegram_id=telegram_id, message=message)
        db.add(ticket)
        db.commit()
        db.refresh(ticket)
    if BOT_TOKEN:
        async with httpx.AsyncClient(timeout=15) as client:
            await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json={"chat_id": ADMIN_TELEGRAM_ID, "text": f"🆘 Обращение #{ticket.id} от <code>{telegram_id}</code>\n\n{message}", "parse_mode": "HTML"})
    return {"ticket_id": ticket.id}

@app.post("/api/admin/tickets/{ticket_id}/reply")
async def reply_ticket(ticket_id: int, body: SupportReply, x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    require_admin(telegram_id)
    reply = body.message.strip()
    if not reply:
        raise HTTPException(422, "Введите ответ.")
    with Session(engine) as db:
        ticket = db.get(SupportTicket, ticket_id)
        if not ticket:
            raise HTTPException(404, "Обращение не найдено.")
        ticket.status = "answered"
        recipient = ticket.telegram_id
        db.commit()
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json={"chat_id": recipient, "text": f"💬 <b>Ответ поддержки</b>\n\n{reply}", "parse_mode": "HTML"})
        response.raise_for_status()
    return {"ok": True}

def demo_text(run: DemoRun) -> str:
    accounts = ", ".join(str(index + 1) for index in json.loads(run.accounts))
    return (f"🟣 <b>Визуальная рассылка #{run.id}</b>\n\n"
            f"🔄 Цикл: <b>{run.cycle}</b>\n"
            f"💬 Условно отправлено: <b>{run.sent_count}</b> чатов\n"
            f"👤 Аккаунты: {accounts}\n"
            f"🛡 Режим: {'Безопасный' if run.mode == 'safe' else 'Обычный'}\n\n"
            f"{'⏹ Симуляция завершена' if run.status == 'stopped' else '▶️ Выполняется визуальная симуляция'}")

async def publish_demo(run: DemoRun):
    if not BOT_TOKEN or not run.telegram_message_id:
        return
    markup = {"inline_keyboard": [[{"text": "⏹ Завершить рассылку", "callback_data": f"demo_stop_{run.id}"}]]} if run.status == "active" else None
    async with httpx.AsyncClient(timeout=15) as client:
        await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/editMessageText", json={"chat_id": run.telegram_id, "message_id": run.telegram_message_id, "text": demo_text(run), "parse_mode": "HTML", "reply_markup": markup})

@app.get("/api/demo-runs")
async def demo_runs(x_telegram_init_data: str | None = Header(default=None)):
    user_id = telegram_user(x_telegram_init_data)
    with Session(engine) as db:
        runs = db.scalars(select(DemoRun).where(DemoRun.telegram_id == user_id, DemoRun.status == "active")).all()
        for run in runs:
            run.cycle += 1
            run.sent_count += len(json.loads(run.accounts)) * 2
        db.commit()
        data = [{"id": run.id, "accounts": json.loads(run.accounts), "mode": run.mode, "interval_minutes": run.interval_minutes, "cycle": run.cycle, "sent_count": run.sent_count, "status": run.status} for run in runs]
        for run in runs:
            await publish_demo(run)
    return data

@app.post("/api/demo-runs")
async def start_demo_run(body: DemoRunStart, x_telegram_init_data: str | None = Header(default=None)):
    user_id = telegram_user(x_telegram_init_data)
    require_terms(user_id)
    if body.mode not in ("normal", "safe") or not body.accounts or any(i not in (0, 1, 2) for i in body.accounts):
        raise HTTPException(422, "Некорректные параметры визуального запуска.")
    with Session(engine) as db:
        run = DemoRun(telegram_id=user_id, accounts=json.dumps(sorted(set(body.accounts))), mode=body.mode, interval_minutes=body.interval_minutes)
        db.add(run); db.commit(); db.refresh(run)
        if BOT_TOKEN:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json={"chat_id": user_id, "text": demo_text(run), "parse_mode": "HTML", "reply_markup": {"inline_keyboard": [[{"text": "⏹ Завершить рассылку", "callback_data": f"demo_stop_{run.id}"}]]}})
                if response.is_success:
                    run.telegram_message_id = response.json()["result"]["message_id"]; db.commit()
        return {"id": run.id}

@app.post("/api/demo-runs/{run_id}/stop")
async def stop_demo_run(run_id: int, x_telegram_init_data: str | None = Header(default=None)):
    user_id = telegram_user(x_telegram_init_data)
    with Session(engine) as db:
        run = db.get(DemoRun, run_id)
        if not run or run.telegram_id != user_id: raise HTTPException(404, "Запуск не найден.")
        run.status = "stopped"; db.commit(); db.refresh(run)
        await publish_demo(run)
    return {"ok": True}

@app.post("/api/keys/activate")
def activate_key(body: KeyActivation, x_telegram_init_data: str | None = Header(default=None)):
    telegram_id = telegram_user(x_telegram_init_data)
    require_terms(telegram_id)
    supplied = body.key.strip().upper()
    with Session(engine) as db:
        manual = db.get(ManualLicenseKey, supplied)
        if manual:
            if manual.used_by:
                raise HTTPException(409, "Этот ключ уже активирован.")
            expiry = None if manual.duration_days == -1 else datetime.now(timezone.utc) + timedelta(days=manual.duration_days)
            db.add(Order(telegram_id=telegram_id, plan="manual", invoice_id=f"manual-{supplied}", status="paid", license_key=supplied, expires_at=expiry))
            manual.used_by = telegram_id
            db.commit()
            return {"key": supplied, "expires_at": expiry}
        order = db.scalar(select(Order).where(Order.license_key == supplied, Order.status == "paid"))
        if not order:
            raise HTTPException(404, "Ключ не найден или ещё не оплачен.")
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
    # Crypto Pay sends {update_type: "invoice_paid", payload: {invoice_id: ...}}.
    # Re-checking the invoice against the API inside activate() makes delivery idempotent.
    if data.get("update_type") == "invoice_paid":
        invoice_id = str(data.get("payload", {}).get("invoice_id", ""))
        if invoice_id:
            await activate(invoice_id)
    return {"ok": True}

@app.post("/api/telegram/webhook/{secret}")
async def telegram_webhook(secret: str, request: Request, x_telegram_bot_api_secret_token: str | None = Header(default=None)):
    """Receives /start and returns an inline Web App button; configured in Telegram setWebhook."""
    # The long, unguessable secret path is the webhook authentication boundary.
    # Header validation is intentionally omitted for compatibility with Telegram delivery.
    if not TELEGRAM_WEBHOOK_SECRET or not hmac.compare_digest(secret, TELEGRAM_WEBHOOK_SECRET):
        raise HTTPException(404, "Не найдено")
    update = await request.json()
    message = update.get("message", {})
    if not message.get("text", "").startswith("/start") or not BOT_TOKEN:
        return {"ok": True}
    chat_id = message.get("chat", {}).get("id")
    if not chat_id:
        return {"ok": True}
    text = ("👋 <b>Добро пожаловать!</b>\n\n"
            "Здесь можно ознакомиться с сервисом, принять соглашение и выбрать лицензию. "
            "Нажмите кнопку ниже, чтобы открыть приложение.")
    # Railway terminates HTTPS at its proxy. Rebuild the public HTTPS address
    # from forwarded headers instead of using the internal http:// container URL.
    forwarded_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "https").split(",")[0].strip()
    web_app_url = f"{forwarded_proto}://{forwarded_host}" if forwarded_host else WEBAPP_URL
    if not web_app_url.startswith("https://"):
        web_app_url = WEBAPP_URL
    if not web_app_url or not web_app_url.startswith("https://"):
        logger.error("No valid public HTTPS WEBAPP_URL is configured.")
        return {"ok": True}
    keyboard = {"inline_keyboard": [[{"text": "🚀 Запустить", "web_app": {"url": web_app_url}}]]}
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json={"chat_id": chat_id, "text": text, "parse_mode": "HTML", "reply_markup": keyboard})
        if not response.is_success:
            logger.error("Telegram /start reply failed: %s", response.text)
            response.raise_for_status()
    return {"ok": True}
