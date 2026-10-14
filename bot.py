# -*- coding: utf-8 -*-
import os
import re
import logging
import sqlite3
import requests
import asyncio
import time as _time
from concurrent.futures import ThreadPoolExecutor
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes, ConversationHandler
)

logging.basicConfig(level=logging.INFO)

BOT_TOKEN        = os.environ.get("BOT_TOKEN")
CRYPTO_BOT_TOKEN = os.environ.get("CRYPTO_BOT_TOKEN", "")

_WORKER_URLS = [
    u.strip() for u in [
        os.environ.get("WORKER_1_URL", ""),
        os.environ.get("WORKER_2_URL", ""),
        os.environ.get("WORKER_3_URL", ""),
        os.environ.get("WORKER_4_URL", ""),
    ] if u.strip()
]
WORKER_SECRET = os.environ.get("WORKER_SECRET", "mysecret")
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
        return (_time.time() - dead_since) >= WORKER_HEALTH_TTL

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

def call_worker_2fa(cookie: str, method: str) -> str | None:
    order = get_worker_order()
    if not order:
        logging.warning("Нет доступных воркеров, используем локальный метод 2FA")
        return get_url_via_api_2fa(cookie, method)

    last_error = None
    for i, worker_url in enumerate(order):
        try:
            logging.info("[%d/%d] Отправляю на воркер: %s", i + 1, len(order), worker_url)
            r = requests.post(
                f"{worker_url}/get-link",
                json={"cookie": cookie, "method": method, "secret": WORKER_SECRET},
                headers={"X-Secret": WORKER_SECRET},
                timeout=620,
            )
            if r.status_code == 200:
                link = r.json().get("link")
                logging.info("Воркер %s вернул ссылку: %s", worker_url, link)
                _mark_worker(worker_url, True)
                return link
            last_error = f"http_{r.status_code}"
            continue
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            _mark_worker(worker_url, False)
            last_error = "unreachable"
            continue
        except Exception as e:
            last_error = str(e)
            continue
    return None

ADMIN_IDS = set(map(int, os.environ.get("ADMIN_IDS", "0").split(",")))
LOG_CHANNEL_ID = os.environ.get("LOG_CHANNEL_ID", "")

executor = ThreadPoolExecutor(max_workers=20)
pending_payments = {}

WAITING_RULES = 0
WAITING_MENU = 1
WAITING_COOKIE = 2
WAITING_BUY = 3
WAITING_PAYMENT = 4
WAITING_PROMO = 5
WAITING_ADMIN = 6
WAITING_ADMIN_BROADCAST = 7
WAITING_ADMIN_ADD_BALANCE = 8
WAITING_ADMIN_ADD_BALANCE_AMOUNT = 9
WAITING_ADMIN_CREATE_PROMO = 10
WAITING_ADMIN_ADD_SUB = 11
WAITING_ADMIN_ADD_SUB_DAYS = 12
WAITING_ADMIN_REMOVE_BALANCE = 13
WAITING_ADMIN_REMOVE_BALANCE_AMOUNT = 14
WAITING_ADMIN_SEARCH_PROMO = 15
WAITING_ADMIN_FILTER_USERS = 16

PRICE_2FA = 1.00
DISCOUNTS_2FA = {5: 0.05, 10: 0.10, 15: 0.15, 25: 0.20}
SUBSCRIPTIONS = {1: 3.00, 3: 5.00, 7: 10.00, 30: 25.00, 0: 50.00}
DB_PATH = "bot_data.db"

def db_init():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY, username TEXT, attempts INTEGER DEFAULT 0, spent REAL DEFAULT 0.0, lang TEXT DEFAULT 'ru')")
    c.execute("CREATE TABLE IF NOT EXISTS promo_codes (code TEXT PRIMARY KEY, attempts INTEGER DEFAULT 1, uses INTEGER DEFAULT 0, max_uses INTEGER DEFAULT 1)")
    c.execute("CREATE TABLE IF NOT EXISTS used_promos (user_id INTEGER, code TEXT, PRIMARY KEY (user_id, code))")
    c.execute("CREATE TABLE IF NOT EXISTS subscriptions (user_id INTEGER PRIMARY KEY, expires_at TEXT, is_forever INTEGER DEFAULT 0)")
    conn.commit()
    conn.close()

def db_get_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, attempts, spent FROM users WHERE user_id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row

def db_upsert_user(user_id, username, attempts_delta=0, spent_delta=0.0):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO users (user_id, username, attempts, spent) VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET username=excluded.username, attempts=attempts + ?, spent=spent + ?
    """, (user_id, username, max(0, attempts_delta), spent_delta, attempts_delta, spent_delta))
    conn.commit()
    conn.close()

def db_get_attempts(user_id):
    row = db_get_user(user_id)
    return row[1] if row else 0

def db_get_all_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user_id, username, attempts, spent FROM users ORDER BY spent DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def db_get_top(limit=10):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user_id, username, spent FROM users WHERE spent > 0 ORDER BY spent DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def db_create_promo(code, attempts, max_uses):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO promo_codes (code, attempts, uses, max_uses) VALUES (?, ?, 0, ?)", (code, attempts, max_uses))
    conn.commit()
    conn.close()

def db_use_promo(user_id, code):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT attempts, uses, max_uses FROM promo_codes WHERE code=?", (code,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "Промокод не найден!", 0
    attempts, uses, max_uses = row
    if uses >= max_uses:
        conn.close()
        return False, "Промокод уже использован!", 0
    c.execute("SELECT 1 FROM used_promos WHERE user_id=? AND code=?", (user_id, code))
    if c.fetchone():
        conn.close()
        return False, "Вы уже использовали этот промокод!", 0
    c.execute("UPDATE promo_codes SET uses=uses+1 WHERE code=?", (code,))
    c.execute("INSERT INTO used_promos (user_id, code) VALUES (?, ?)", (user_id, code))
    conn.commit()
    conn.close()
    return True, "OK", attempts

def db_get_all_promos():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT code, attempts, uses, max_uses FROM promo_codes")
    rows = c.fetchall()
    conn.close()
    return rows

def db_delete_promo(code):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM promo_codes WHERE code=?", (code,))
    conn.commit()
    conn.close()

def db_get_subscription(user_id):
    import datetime
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT expires_at, is_forever FROM subscriptions WHERE user_id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, None, False
    expires_at_str, is_forever = row
    if is_forever:
        return True, "Навсегда", True
    if expires_at_str:
        try:
            exp = datetime.datetime.fromisoformat(expires_at_str)
            if exp > datetime.datetime.utcnow():
                return True, expires_at_str, False
        except Exception:
            pass
    return False, expires_at_str, False

def db_set_subscription(user_id, days):
    import datetime
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if days == 0:
        c.execute("INSERT INTO subscriptions (user_id, expires_at, is_forever) VALUES (?, NULL, 1) ON CONFLICT(user_id) DO UPDATE SET expires_at=NULL, is_forever=1", (user_id,))
    else:
        c.execute("SELECT expires_at, is_forever FROM subscriptions WHERE user_id=?", (user_id,))
        existing = c.fetchone()
        now = datetime.datetime.utcnow()
        if existing and not existing[1] and existing[0]:
            try:
                exp = datetime.datetime.fromisoformat(existing[0])
                if exp > now:
                    now = exp
            except Exception:
                pass
        new_exp = (now + datetime.timedelta(days=days)).isoformat()
        c.execute("INSERT INTO subscriptions (user_id, expires_at, is_forever) VALUES (?, ?, 0) ON CONFLICT(user_id) DO UPDATE SET expires_at=?, is_forever=0", (user_id, new_exp, new_exp))
    conn.commit()
    conn.close()

def db_get_lang(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT lang FROM users WHERE user_id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else "ru"

def db_set_lang(user_id, lang):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET lang=? WHERE user_id=?", (lang, user_id))
    conn.commit()
    conn.close()

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
        "buy_discount": "Скидки на пакеты: 5 шт −5%, 10 шт −10%, 15 шт −15%, 25 шт −20%",
        "promo_title": "*Активация промокода*",
        "promo_enter": "Введите промокод:",
        "promo_ok": "Промокод активирован! +*{attempts}* попыток\nВсего: *{total}*",
        "promo_not_found": "Промокод не найден!",
        "promo_used": "Промокод уже использован!",
        "promo_used_by_you": "Вы уже использовали этот промокод!",
        "checking_cookie": "Проверяю cookie...",
        "invalid_cookie": "Неверный cookie! Попробуй снова.\n\n/start",
        "processing": "Аккаунт: *{name}*\nМетод: *{method}*\nОсталось попыток: *{attempts}*\n\nЖди 20-30 сек...",
        "browser_fallback": "API не ответил, открываю браузер...",
        "error_returned": "Техническая ошибка - попытка возвращена!\n\nПричина: {reason}\n\n/start",
        "not_clicked_returned": "Кнопка не найдена - попытка возвращена!\n\n/start",
        "link_received": "*Ссылка получена!*\n\n⏱ Действует *10 минут* — используй сразу!\n🔗 Одноразовая ссылка:",
        "failed_returned": "❌ Не удалось получить ссылку — попытка возвращена!",
        "method_camera": "Camera",
        "method_id": "ID",
        "service_camera": "Ссылка Camera (Лицо)",
        "service_id": "Ссылка ID (Паспорт)",
        "log_success": "✅ УСПЕШНО",
        "log_fail": "❌ НЕУДАЧА",
        "log_result_ok": "Ссылка получена",
        "log_result_fail": "Не удалось получить ссылку",
        "anon": "Аноним",
        "choose_method": "*Выберите метод верификации:*",
        "btn_camera": "📷 Camera (Лицо)",
        "btn_id": "🪪 ID (Паспорт)",
        "invoice_created": "*Счёт создан!*\n\nСумма: *${amount}*\nПопыток: *{attempts}*",
        "btn_check_pay": "✅ Проверить оплату",
        "btn_pay": "💳 Оплатить",
        "pay_ok": "*Оплата получена!*\nНачислено *{attempts}* попыток\nВсего: *{total}*",
        "pay_pending": "Оплата ещё не получена. Попробуй позже.",
        "pay_error": "Ошибка создания счёта!",
        "lang_choose": "🌐 Выберите язык / Choose language:",
        "lang_set": "✅ Язык установлен: Русский",
        "cancelled": "Отменено. /start",
        "ask_2fa": "На каком аккаунте получить ссылку?",
        "btn_no_2fa": "🔓 Без 2FA",
        "btn_with_2fa": "🔐 С 2FA",
        "2fa_ask_cookie": "🔐 *Режим 2FA*\n\nОтправь `.ROBLOSECURITY` cookie",
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
        "buy_discount": "Discounts: 5 pcs −5%, 10 pcs −10%, 15 pcs −15%, 25 pcs −20%",
        "promo_title": "*Promo code activation*",
        "promo_enter": "Enter promo code:",
        "promo_ok": "Promo activated! +*{attempts}* attempts\nTotal: *{total}*",
        "promo_not_found": "Promo code not found!",
        "promo_used": "Promo code already used!",
        "promo_used_by_you": "You have already used this promo code!",
        "checking_cookie": "Checking cookie...",
        "invalid_cookie": "Invalid cookie! Try again.\n\n/start",
        "processing": "Account: *{name}*\nMethod: *{method}*\nAttempts left: *{attempts}*\n\nPlease wait 20-30 sec...",
        "browser_fallback": "API didn't respond, opening browser...",
        "error_returned": "Technical error - attempt returned!\n\nReason: {reason}\n\n/start",
        "not_clicked_returned": "Button not found - attempt returned!\n\n/start",
        "link_received": "*Link received!*\n\n⏱ Valid for *10 minutes* — use it now!\n🔗 One-time link:",
        "failed_returned": "❌ Failed to get link — attempt returned!",
        "method_camera": "Camera",
        "method_id": "ID",
        "service_camera": "Camera link (Face)",
        "service_id": "ID link (Passport)",
        "log_success": "✅ SUCCESS",
        "log_fail": "❌ FAILURE",
        "log_result_ok": "Link received",
        "log_result_fail": "Failed to get link",
        "anon": "Anonymous",
        "choose_method": "*Choose verification method:*",
        "btn_camera": "📷 Camera (Face)",
        "btn_id": "🪪 ID (Passport)",
        "invoice_created": "*Invoice created!*\n\nAmount: *${amount}*\nAttempts: *{attempts}*",
        "btn_check_pay": "✅ Check payment",
        "btn_pay": "💳 Pay",
        "pay_ok": "*Payment received!*\nAdded *{attempts}* attempts\nTotal: *{total}*",
        "pay_pending": "Payment not received yet. Try later.",
        "pay_error": "Invoice creation error!",
        "lang_choose": "🌐 Выберите язык / Choose language:",
        "lang_set": "✅ Language set: English",
        "cancelled": "Cancelled. /start",
        "ask_2fa": "Which account type do you want to verify?",
        "btn_no_2fa": "🔓 Without 2FA",
        "btn_with_2fa": "🔐 With 2FA",
        "2fa_ask_cookie": "🔐 *2FA Mode*\n\nSend your `.ROBLOSECURITY` cookie",
    }
}

def t(user_id, key, **kwargs):
    lang = db_get_lang(user_id)
    text = TEXTS.get(lang, TEXTS["ru"]).get(key, TEXTS["ru"].get(key, key))
    if kwargs:
        text = text.format(**kwargs)
    return text

def t_lang(lang, key, **kwargs):
    text = TEXTS.get(lang, TEXTS["ru"]).get(key, TEXTS["ru"].get(key, key))
    if kwargs:
        text = text.format(**kwargs)
    return text

def get_link_via_api(cookie, method):
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
            link = extract_link_from_raw(r1.text)
            if link:
                return link
        if csrf:
            s.headers["x-csrf-token"] = csrf
            r2 = s.post(url, json=body, timeout=12)
            if r2.status_code == 200:
                return extract_link_from_raw(r2.text)
        return None
    except Exception as e:
        logging.error("API error: %s", e)
        return None

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
        link = "https://inquiry.withpersona.com/verify?inquiry-id=" + inq_id
        if tok_m:
            link += "&session-token=" + tok_m.group(1)
        return link
    return None

def create_invoice(amount, attempts):
    try:
        r = requests.post(
            "https://pay.crypt.bot/api/createInvoice",
            headers={"Crypto-Pay-API-Token": CRYPTO_BOT_TOKEN},
            json={"asset": "USDT", "amount": str(round(amount, 2)), "description": f"Pokupka {attempts} popytok", "expires_in": 300}
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
            params={"invoice_ids": invoice_id}
        )
        data = r.json()
        return data["result"]["items"][0] if data.get("ok") and data["result"]["items"] else None
    except Exception:
        return None

async def send_log(bot, user_id, username, method, result, elapsed_sec, success, has_2fa=False):
    if not LOG_CHANNEL_ID or not success:
        return
    try:
        cost = "$1.00" if has_2fa else "БЕСПЛАТНО"
        service = "Camera" if method == "camera" else "ID"
        msg = f"✅ УСПЕШНО\n━━━━━━━━━━━━━━━━━━━━━━\n👤 ID: {user_id} (@{username})\n⚙️ Услуга: {service}\n✅ Результат: Ссылка получена\n⏲️ Время: {round(elapsed_sec)} сек\n💳 Сумма: {cost}"
        await bot.send_message(chat_id=LOG_CHANNEL_ID, text=msg)
    except Exception:
        pass

def main_menu_kb(user_id=None):
    lang = db_get_lang(user_id) if user_id else "ru"
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
    lang = db_get_lang(user_id)
    if is_active and is_forever:
        return "∞", ("♾️ Forever" if lang == "en" else "♾️ Навсегда")
    elif is_active:
        try:
            exp = _dt.datetime.fromisoformat(expires)
            delta = exp - _dt.datetime.utcnow()
            total_min = max(0, int(delta.total_seconds() // 60))
            h, m = divmod(total_min, 60)
            remaining = f"{h}h {m}m" if lang == "en" else f"{h}ч {m}мин"
        except Exception:
            remaining = "?"
        return "∞", remaining
    else:
        return str(attempts), ("No sub" if lang == "en" else "Нет под.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    tg = update.effective_user
    db_upsert_user(user_id, tg.username or tg.first_name or "Аноним")
    attempts, sub_status = _sub_status_text(user_id)
    text = f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_sub')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}"
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
    return WAITING_MENU

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    tg = update.effective_user
    username = tg.username or tg.first_name or "Аноним"
    data = query.data

    if data.startswith("set_lang_"):
        lang = data.split("_")[2]
        db_set_lang(user_id, lang)
        await query.edit_message_text(TEXTS[lang]["lang_set"], reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(TEXTS[lang]["btn_back"], callback_data="main_menu")]]))
        return WAITING_MENU

    if data in ["main_menu", "accept_rules"]:
        attempts, sub_status = _sub_status_text(user_id)
        text = f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_sub')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
        return WAITING_MENU

    if data == "help":
        await query.edit_message_text(t(user_id, "help_text"), parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
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
                lines.append(f"{medal} {uname or t(user_id, 'anon')} - ${round(spent, 2)}")
        await query.edit_message_text("\n".join(lines), parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        return WAITING_MENU

    if data == "promo":
        context.user_data["waiting"] = "promo"
        await query.edit_message_text(f"{t(user_id, 'promo_title')}\n\n{t(user_id, 'promo_enter')}", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        return WAITING_PROMO

    if data == "buy":
        await query.edit_message_text(f"{t(user_id, 'buy_title')}\n\n{t(user_id, 'buy_price')}\n\n{t(user_id, 'buy_discount')}", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton(t(user_id, "btn_buy_attempts"), callback_data="buy_attempts")],
            [InlineKeyboardButton(t(user_id, "btn_buy_sub"), callback_data="buy_sub")],
            [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")],
        ]))
        return WAITING_BUY

    if data == "buy_attempts":
        await query.edit_message_text("🎯 Выберите пакет попыток:", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton(t(user_id, "btn_buy_1"), callback_data="buy_1")],
            [InlineKeyboardButton(t(user_id, "btn_buy_5"), callback_data="buy_5")],
            [InlineKeyboardButton(t(user_id, "btn_buy_10"), callback_data="buy_10")],
            [InlineKeyboardButton(t(user_id, "btn_buy_15"), callback_data="buy_15")],
            [InlineKeyboardButton(t(user_id, "btn_buy_25"), callback_data="buy_25")],
            [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy")],
        ]))
        return WAITING_BUY

    if data == "buy_sub":
        await query.edit_message_text("♾️ Выберите период подписки:", reply_markup=InlineKeyboardMarkup([
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
        pending_payments[inv_key] = {"type": "sub", "days": days, "price": price, "desc": desc}
        await query.edit_message_text(f"Счёт на подписку: {desc}\nСумма: ${price}", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton(t(user_id, "btn_pay"), url=invoice["pay_url"])],
            [InlineKeyboardButton(t(user_id, "btn_check_pay"), callback_data=f"check_{inv_key}")],
            [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy_sub")],
        ]))
        return WAITING_PAYMENT

    if data.startswith("buy_") and not data.startswith("buy_attempts") and not data.startswith("buy_sub"):
        count = int(data.split("_")[1])
        discount = DISCOUNTS_2FA.get(count, 0)
        total = round(count * PRICE_2FA * (1 - discount), 2)
        raw = create_invoice(total, count)
        if not raw:
            await query.answer(t(user_id, "pay_error"), show_alert=True)
            return WAITING_BUY
        inv_key = f"cb_{raw['invoice_id']}"
        pending_payments[inv_key] = {"user_id": user_id, "attempts": count, "total": total}
        await query.edit_message_text(t(user_id, "invoice_created", amount=f"{total:.2f}", attempts=count), reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton(t(user_id, "btn_pay"), url=raw["pay_url"])],
            [InlineKeyboardButton(t(user_id, "btn_check_pay"), callback_data=f"check_{inv_key}")],
            [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy")],
        ]))
        return WAITING_PAYMENT

    if data.startswith("check_"):
        inv_key = data[6:]
        payment = pending_payments.get(inv_key, {})
        raw_id = "_".join(inv_key.split("_")[1:])
        inv = check_invoice(raw_id)
        if inv and inv.get("status") == "paid":
            payment = pending_payments.pop(inv_key, None)
            if payment.get("type") == "sub":
                db_set_subscription(user_id, payment["days"])
                db_upsert_user(user_id, username, spent_delta=payment["price"])
                await query.edit_message_text(t(user_id, "sub_bought", desc=payment["desc"]), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
            else:
                cnt = payment["attempts"]
                db_upsert_user(user_id, username, attempts_delta=cnt, spent_delta=payment["total"])
                await query.edit_message_text(t(user_id, "pay_ok", attempts=cnt, total=db_get_attempts(user_id)), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        else:
            await query.answer(t(user_id, "pay_pending"), show_alert=True)
        return WAITING_MENU

    if data == "get_link":
        await query.edit_message_text(t(user_id, "ask_2fa"), reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton(t(user_id, "btn_no_2fa"), callback_data="2fa_no"), InlineKeyboardButton(t(user_id, "btn_with_2fa"), callback_data="2fa_yes")],
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
        await query.edit_message_text(t(user_id, "2fa_ask_cookie"), parse_mode="Markdown")
        return WAITING_COOKIE

    if data == "admin":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        rows = db_get_all_users()
        await query.edit_message_text(f"Админ панель\nПользователей: {len(rows)}", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("Список промокодов", callback_data="admin_promo_list")],
            [InlineKeyboardButton("Создать промокод", callback_data="admin_promo")],
            [InlineKeyboardButton("Назад", callback_data="main_menu")],
        ]))
        return WAITING_ADMIN

    if data == "admin_promo_list":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        rows = db_get_all_promos()
        lines = ["Список промокодов:"]
        for code, atts, uses, max_uses in rows:
            lines.append(f"`{code}` - {atts} поп. | {uses}/{max_uses}")
        await query.edit_message_text("\n".join(lines), parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]]))
        return WAITING_ADMIN

    if data == "admin_promo":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "create_promo"
        await query.edit_message_text("Введите промокод в формате: `КОД ПОПЫТКИ ИСПОЛЬЗОВАНИЙ`", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]]))
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
        ok, msg_key, atts = db_use_promo(user_id, text.upper())
        if ok:
            db_upsert_user(user_id, username, attempts_delta=atts)
            await update.message.reply_text(t(user_id, "promo_ok", attempts=atts, total=db_get_attempts(user_id)), parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        else:
            await update.message.reply_text(t(user_id, "promo_not_found"), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]))
        return WAITING_MENU

    if waiting == "create_promo" and user_id in ADMIN_IDS:
        context.user_data["waiting"] = None
        parts = text.split()
        db_create_promo(parts[0].upper(), int(parts[1]) if len(parts) > 1 else 1, int(parts[2]) if len(parts) > 2 else 1)
        await update.message.reply_text("✅ Промокод создан!", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("В админку", callback_data="admin")]]))
        return WAITING_ADMIN

    return await receive_cookie(update, context)

async def receive_cookie(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cookie = update.message.text.strip()
    method = context.user_data.get("method")
    has_2fa = context.user_data.get("has_2fa", False)
    user_id = update.effective_user.id
    tg = update.effective_user
    username = tg.username or tg.first_name or "Аноним"

    if not method:
        await show_main_menu(update, context)
        return WAITING_MENU

    try:
        await update.message.delete()
    except Exception:
        pass

    msg = await update.message.reply_text(t(user_id, "checking_cookie"))

    s = requests.Session()
    s.cookies[".ROBLOSECURITY"] = cookie
    r = s.get("https://users.roblox.com/v1/users/authenticated")
    if r.status_code != 200:
        await msg.edit_text(t(user_id, "invalid_cookie"))
        return WAITING_MENU

    user = r.json()
    method_name = t(user_id, "method_camera") if method == "camera" else t(user_id, "method_id")

    if has_2fa:
        is_sub_active, _, _ = db_get_subscription(user_id)
        if not is_sub_active:
            if db_get_attempts(user_id) <= 0:
                await msg.edit_text("❌ Нет попыток 2FA!")
                return WAITING_MENU
            db_upsert_user(user_id, username, attempts_delta=-1, spent_delta=PRICE_2FA)

    await msg.edit_text(t(user_id, "processing", name=user["name"], method=method_name, attempts=db_get_attempts(user_id)), parse_mode="Markdown")

    loop = asyncio.get_event_loop()
    _start_time = _time.time()

    if has_2fa:
        result = await loop.run_in_executor(executor, call_worker_2fa, cookie, method)
    else:
        result = await loop.run_in_executor(executor, get_link_via_api, cookie, method)

    elapsed = round(_time.time() - _start_time)

    if result and "withpersona.com" in result:
        await msg.edit_text(t(user_id, "link_received"), parse_mode="Markdown")
        await update.message.reply_text(result)
        _sub_active, _, _ = db_get_subscription(user_id)
        await send_log(update.get_bot(), user_id, username, method, t(user_id, "log_result_ok"), elapsed, True, has_2fa=has_2fa)
        attempts, sub_status = _sub_status_text(user_id)
        await update.message.reply_text(f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}", parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
        return WAITING_MENU

    if has_2fa and not db_get_subscription(user_id)[0]:
        db_upsert_user(user_id, username, attempts_delta=1, spent_delta=-PRICE_2FA)

    await msg.edit_text(t(user_id, "failed_returned"))
    attempts, sub_status = _sub_status_text(user_id)
    await update.message.reply_text(f"{t(user_id, 'main_menu_title')}\n\n{t(user_id, 'main_menu_attempts', attempts=attempts, sub_status=sub_status)}\n\n{t(user_id, 'main_menu_action')}", parse_mode="Markdown", reply_markup=main_menu_kb(user_id))
    return WAITING_MENU

async def lan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🌐 Выберите язык:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🇷🇺 Русский", callback_data="set_lang_ru"), InlineKeyboardButton("🇬🇧 English", callback_data="set_lang_en")]]))
    return WAITING_MENU

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Отменено. /start")
    return ConversationHandler.END

def main():
    db_init()
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    conv = ConversationHandler(
        entry_points=[CommandHandler("start", start), CommandHandler("lan", lan_command)],
        states={
            WAITING_MENU: [CallbackQueryHandler(handle_callback)],
            WAITING_COOKIE: [CallbackQueryHandler(handle_callback), MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_BUY: [CallbackQueryHandler(handle_callback)],
            WAITING_PAYMENT: [CallbackQueryHandler(handle_callback)],
            WAITING_PROMO: [CallbackQueryHandler(handle_callback), MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN: [CallbackQueryHandler(handle_callback), MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN_CREATE_PROMO: [CallbackQueryHandler(handle_callback), MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
        },
        fallbacks=[CommandHandler("cancel", cancel), CommandHandler("start", start)],
        per_user=True, per_chat=True, block=False,
    )
    app.add_handler(conv)
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
