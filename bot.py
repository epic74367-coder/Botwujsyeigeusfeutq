# -*- coding: utf-8 -*-
import os
import re
import logging
import sqlite3
import requests
import asyncio
import random
import string
from concurrent.futures import ThreadPoolExecutor
from playwright.sync_api import sync_playwright
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes, ConversationHandler
)

logging.basicConfig(level=logging.INFO)


BOT_TOKEN        = os.environ.get("BOT_TOKEN")
CRYPTO_BOT_TOKEN = os.environ.get("CRYPTO_BOT_TOKEN", "")

# ===== 2FA ВОРКЕРЫ =====
# URL берём из env переменных Railway: WORKER_1_URL, WORKER_2_URL, ...
# Пример: https://worker1.up.railway.app
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

# ── health-кэш: какие воркеры живы прямо сейчас (в памяти процесса) ─────────
_worker_health = {url: True for url in _WORKER_URLS}
_worker_health_lock = __import__("threading").Lock()
WORKER_HEALTH_TTL = int(os.environ.get("WORKER_HEALTH_TTL", 30))  # через сколько сек снова пробовать "мёртвый"
_worker_dead_since: dict[str, float] = {}


def _mark_worker(url: str, alive: bool):
    with _worker_health_lock:
        _worker_health[url] = alive
        if alive:
            _worker_dead_since.pop(url, None)
        else:
            _worker_dead_since.setdefault(url, __import__("time").time())


def _worker_considered_alive(url: str) -> bool:
    """Мёртвый воркер снова пробуем через WORKER_HEALTH_TTL сек — вдруг его включили обратно."""
    with _worker_health_lock:
        if _worker_health.get(url, True):
            return True
        dead_since = _worker_dead_since.get(url, 0)
        return (__import__("time").time() - dead_since) >= WORKER_HEALTH_TTL


def get_worker_order() -> list[str]:
    """Round-robin порядок воркеров; живые — впереди мёртвых."""
    global _worker_index
    if not _WORKER_URLS:
        return []
    with _worker_lock:
        start = _worker_index % len(_WORKER_URLS)
        _worker_index += 1
    ordered = _WORKER_URLS[start:] + _WORKER_URLS[:start]
    alive = [u for u in ordered if _worker_considered_alive(u)]
    dead  = [u for u in ordered if u not in alive]
    return alive + dead  # мёртвых тоже пробуем последними — вдруг их уже подняли


def call_worker_2fa(cookie: str, method: str) -> str | None:
    """
    Round-robin + failover: если воркер выключен/недоступен —
    сразу переключается на следующий, пока не получит ответ
    или не кончится список воркеров.
    """
    order = get_worker_order()
    if not order:
        logging.warning("Нет доступных воркеров, используем локальный метод")
        return get_url_via_api_2fa(cookie, method)

    last_error = None
    for i, worker_url in enumerate(order):
        try:
            logging.info("[%d/%d] Отправляю на воркер: %s", i + 1, len(order), worker_url)
            r = requests.post(
                f"{worker_url}/get-link",
                json={"cookie": cookie, "method": method, "secret": WORKER_SECRET},
                headers={"X-Secret": WORKER_SECRET},
                timeout=620,  # чуть больше DEADLINE воркера
            )
            if r.status_code == 200:
                link = r.json().get("link")
                logging.info("Воркер %s вернул ссылку: %s", worker_url, link)
                _mark_worker(worker_url, True)
                return link

            logging.error("Воркер %s вернул ошибку %d: %s", worker_url, r.status_code, r.text[:200])
            last_error = f"http_{r.status_code}"
            # сервер ответил (жив), просто не нашёл ссылку — не помечаем мёртвым,
            # но пробуем следующий воркер на случай если там получится быстрее
            continue

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # сервер реально недоступен/выключен — сразу переключаемся
            logging.warning("Воркер %s недоступен (%s) — переключаюсь на следующий",
                             worker_url, type(e).__name__)
            _mark_worker(worker_url, False)
            last_error = "unreachable"
            continue
        except Exception as e:
            logging.error("Ошибка связи с воркером %s: %s", worker_url, e)
            last_error = str(e)
            continue

    logging.error("Все %d воркер(ов) не дали результата (last_error=%s)", len(order), last_error)
    return None

ADMIN_IDS = set(map(int, os.environ.get("ADMIN_IDS", "0").split(",")))
LOG_CHANNEL_ID = os.environ.get("LOG_CHANNEL_ID", "")  # ID канала для логов

# 20 потоков для одновременной работы
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
WAITING_ADMIN_FILTER_USERS = 13
WAITING_ADMIN_SEARCH_PROMO = 14

# Без 2FA — БЕСПЛАТНО
# С 2FA — $1 за попытку
PRICE_2FA = 1.00
DISCOUNTS_2FA = {5: 0.05, 10: 0.10, 15: 0.15, 25: 0.20}

# Подписки на безлимит 2FA: {дней: цена} (0 = навсегда)
SUBSCRIPTIONS = {
    1:  3.00,   # 1 день
    3:  5.00,   # 3 дня
    7:  10.00,  # 7 дней
    30: 25.00,  # 30 дней
    0:  50.00,  # Навсегда
}

DB_PATH = "bot_data.db"

# ===== БАЗА ДАННЫХ =====

def db_init():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            attempts INTEGER DEFAULT 0,
            spent REAL DEFAULT 0.0,
            lang TEXT DEFAULT 'ru'
        )
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
            user_id INTEGER,
            code TEXT,
            PRIMARY KEY (user_id, code)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS subscriptions (
            user_id INTEGER PRIMARY KEY,
            expires_at TEXT,
            is_forever INTEGER DEFAULT 0
        )
    """)
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
        INSERT INTO users (user_id, username, attempts, spent)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            username=excluded.username,
            attempts=attempts + ?,
            spent=spent + ?
    """, (user_id, username, max(0, attempts_delta), spent_delta,
          attempts_delta, spent_delta))
    conn.commit()
    conn.close()

def db_set_attempts(user_id, username, new_attempts):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO users (user_id, username, attempts, spent)
        VALUES (?, ?, ?, 0.0)
        ON CONFLICT(user_id) DO UPDATE SET
            username=excluded.username,
            attempts=?
    """, (user_id, username, new_attempts, new_attempts))
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

def db_get_promo(code):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT attempts, uses, max_uses FROM promo_codes WHERE code=?", (code,))
    row = c.fetchone()
    conn.close()
    return row

def db_create_promo(code, attempts, max_uses):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO promo_codes (code, attempts, uses, max_uses)
        VALUES (?, ?, 0, ?)
    """, (code, attempts, max_uses))
    conn.commit()
    conn.close()

def db_use_promo(user_id, code):
    """Возвращает (успех, сообщение, кол-во попыток)"""
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

def db_get_subscription(user_id):
    """Возвращает (is_active, expires_at_str, is_forever)"""
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
    """Устанавливает подписку. days=0 — навсегда."""
    import datetime
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if days == 0:
        c.execute("""
            INSERT INTO subscriptions (user_id, expires_at, is_forever)
            VALUES (?, NULL, 1)
            ON CONFLICT(user_id) DO UPDATE SET expires_at=NULL, is_forever=1
        """, (user_id,))
    else:
        # Если есть активная подписка — продлеваем
        c.execute("SELECT expires_at, is_forever FROM subscriptions WHERE user_id=?", (user_id,))
        existing = c.fetchone()
        now = datetime.datetime.utcnow()
        if existing and not existing[1] and existing[0]:
            try:
                exp = datetime.datetime.fromisoformat(existing[0])
                if exp > now:
                    now = exp  # продлеваем от текущего конца
            except Exception:
                pass
        new_exp = (now + datetime.timedelta(days=days)).isoformat()
        c.execute("""
            INSERT INTO subscriptions (user_id, expires_at, is_forever)
            VALUES (?, ?, 0)
            ON CONFLICT(user_id) DO UPDATE SET expires_at=?, is_forever=0
        """, (user_id, new_exp, new_exp))
    conn.commit()
    conn.close()


def db_delete_promo(code):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM promo_codes WHERE code=?", (code,))
    conn.commit()
    conn.close()

def db_search_promos(query: str):
    """Ищет промокоды по подстроке (case-insensitive)."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT code, attempts, uses, max_uses FROM promo_codes WHERE UPPER(code) LIKE ?",
        ("%" + query.upper() + "%",)
    )
    rows = c.fetchall()
    conn.close()
    return rows

def db_filter_users_by_attempts(min_attempts: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT user_id, username, attempts, spent FROM users WHERE attempts >= ? ORDER BY attempts DESC",
        (min_attempts,)
    )
    rows = c.fetchall()
    conn.close()
    return rows

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


# ===== ТЕКСТЫ =====

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
        "btn_to_admin": "В админку",
        "btn_buy_1": "1 попытка 2FA — $1.00",
        "btn_buy_5": "5 попыток 2FA — $4.75 (−5%)",
        "btn_buy_10": "10 попыток 2FA — $9.00 (−10%)",
        "btn_buy_15": "15 попыток 2FA — $12.75 (−15%)",
        "btn_buy_25": "25 попыток 2FA — $20.00 (−20%)",
        "btn_sub_1d":  "📅 1 день — $3.00",
        "btn_sub_3d":  "📅 3 дня — $5.00",
        "btn_sub_7d":  "📅 7 дней — $10.00",
        "btn_sub_30d": "📅 30 дней — $25.00",
        "btn_sub_inf": "♾️ Навсегда — $50.00",
        "btn_buy_attempts": "🎯 Попытки 2FA",
        "btn_buy_sub": "♾️ Подписка (безлимит)",
        "sub_active": "✅ Подписка активна до: *{expires}*",
        "sub_active_forever": "✅ Подписка: *Навсегда*",
        "sub_none": "❌ Подписки нет",
        "sub_bought": "✅ Подписка активирована!\n{desc}",
        "help_text": (
            "*Помощь*\n\n"
            "*Тарифы:*\n"
            "🔓 Без 2FA — *БЕСПЛАТНО*\n"
            "🔐 С 2FA — *$1.00* за попытку\n"
            "♾️ Подписка 2FA — безлимит\n\n"
            "*Как пользоваться:*\n"
            "1. Нажмите Получить ссылку\n"
            "2. Выберите тип аккаунта\n"
            "3. Отправьте `.ROBLOSECURITY` cookie\n"
            "4. Выберите Camera или ID\n"
            "5. Получите ссылку на верификацию\n\n"
            "*Важно:*\n"
            "- При технической ошибке попытка возвращается\n"
            "- При невалидном cookie попытка возвращается\n"
            "- Переведите страницу на English и нажмите Reset\n"
            "- Владелец не несёт ответственности за поломку cookie"
        ),
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
        "no_attempts": "Нет попыток!",
        "btn_buy_short": "Купить",
        "checking_cookie": "Проверяю cookie...",
        "invalid_cookie": "Неверный cookie! Попробуй снова.\n\n/start",
        "processing": "Аккаунт: *{name}*\nМетод: *{method}*\nОсталось попыток: *{attempts}*\n\nЖди 20-30 сек...",
        "browser_fallback": "API не ответил, открываю браузер...\nЖди до 30 сек...",
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
        "invoice_created": "*Счёт создан!*\n\nСумма: *${amount}*\nПопыток: *{attempts}*\n\nОплати и нажми Проверить оплату:",
        "btn_check_pay": "✅ Проверить оплату",
        "btn_pay": "💳 Оплатить",
        "pay_ok": "*Оплата получена!*\nНачислено *{attempts}* попыток\nВсего: *{total}*",
        "pay_pending": "Оплата ещё не получена. Попробуй позже.",
        "pay_error": "Ошибка создания счёта!",
        "choose_pay_method": "💳 *Выберите способ оплаты:*\n\n*{count}* попыток — *${usd}*",
        "btn_cryptobot": "🤖 CryptoBot (USDT)",
        "creating_invoice": "⏳ Создаю счёт...",
        "lang_choose": "🌐 Выберите язык / Choose language:",
        "lang_set": "✅ Язык установлен: Русский",
        "cancelled": "Отменено. /start",
        "ask_2fa": "На каком аккаунте получить ссылку?",
        "btn_no_2fa": "🔓 Без 2FA",
        "btn_with_2fa": "🔐 С 2FA",
        "2fa_ask_cookie": "🔐 *Режим 2FA*\n\nОтправь `.ROBLOSECURITY` cookie\nСообщение будет удалено автоматически",
        "2fa_wip": "⚙️ Функция в доработке!\n\nПоддержка аккаунтов с 2FA скоро появится.",
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
        "btn_to_admin": "To admin",
        "btn_buy_1": "1 2FA attempt — $1.00",
        "btn_buy_5": "5 2FA attempts — $4.75 (−5%)",
        "btn_buy_10": "10 2FA attempts — $9.00 (−10%)",
        "btn_buy_15": "15 2FA attempts — $12.75 (−15%)",
        "btn_buy_25": "25 2FA attempts — $20.00 (−20%)",
        "btn_sub_1d":  "📅 1 day — $3.00",
        "btn_sub_3d":  "📅 3 days — $5.00",
        "btn_sub_7d":  "📅 7 days — $10.00",
        "btn_sub_30d": "📅 30 days — $25.00",
        "btn_sub_inf": "♾️ Forever — $50.00",
        "btn_buy_attempts": "🎯 2FA Attempts",
        "btn_buy_sub": "♾️ Subscription (unlimited)",
        "sub_active": "✅ Subscription active until: *{expires}*",
        "sub_active_forever": "✅ Subscription: *Forever*",
        "sub_none": "❌ No subscription",
        "sub_bought": "✅ Subscription activated!\n{desc}",
        "help_text": (
            "*Help*\n\n"
            "*Pricing:*\n"
            "🔓 Without 2FA — *FREE*\n"
            "🔐 With 2FA — *$1.00* per attempt\n"
            "♾️ 2FA Subscription — unlimited\n\n"
            "*How to use:*\n"
            "1. Press Get link\n"
            "2. Choose account type\n"
            "3. Send your `.ROBLOSECURITY` cookie\n"
            "4. Choose Camera or ID\n"
            "5. Get the verification link\n\n"
            "*Important:*\n"
            "- Attempt is returned on technical error\n"
            "- Attempt is returned on invalid cookie\n"
            "- Translate the page to English and click Reset\n"
            "- Owner is not responsible for cookie damage"
        ),
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
        "no_attempts": "No attempts left!",
        "btn_buy_short": "Buy",
        "checking_cookie": "Checking cookie...",
        "invalid_cookie": "Invalid cookie! Try again.\n\n/start",
        "processing": "Account: *{name}*\nMethod: *{method}*\nAttempts left: *{attempts}*\n\nPlease wait 20-30 sec...",
        "browser_fallback": "API didn't respond, opening browser...\nWait up to 30 sec...",
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
        "invoice_created": "*Invoice created!*\n\nAmount: *${amount}*\nAttempts: *{attempts}*\n\nPay and press Check payment:",
        "btn_check_pay": "✅ Check payment",
        "btn_pay": "💳 Pay",
        "pay_ok": "*Payment received!*\nAdded *{attempts}* attempts\nTotal: *{total}*",
        "pay_pending": "Payment not received yet. Try later.",
        "pay_error": "Invoice creation error!",
        "choose_pay_method": "💳 *Choose payment method:*\n\n*{count}* attempts — *${usd}*",
        "btn_cryptobot": "🤖 CryptoBot (USDT)",
        "creating_invoice": "⏳ Creating invoice...",
        "lang_choose": "🌐 Выберите язык / Choose language:",
        "lang_set": "✅ Language set: English",
        "cancelled": "Cancelled. /start",
        "ask_2fa": "Which account type do you want to verify?",
        "btn_no_2fa": "🔓 Without 2FA",
        "btn_with_2fa": "🔐 With 2FA",
        "2fa_ask_cookie": "🔐 *2FA Mode*\n\nSend your `.ROBLOSECURITY` cookie\nMessage will be deleted automatically",
        "2fa_wip": "⚙️ Feature in development!\n\nSupport for 2FA accounts is coming soon.",
    }
}

def t(user_id, key, **kwargs):
    """Получить текст на языке пользователя"""
    lang = db_get_lang(user_id)
    text = TEXTS.get(lang, TEXTS["ru"]).get(key, TEXTS["ru"].get(key, key))
    if kwargs:
        text = text.format(**kwargs)
    return text


# ===== PLAYWRIGHT =====

INJECT_SCRIPT = r"""
(function() {
    window.__capturedData = null;
    var TARGET = 'age-verification-service/v1/persona-id-verification/start-verification';
    function extractLinks(text) {
        var links = [];
        try {
            var data = JSON.parse(text);
            var find = function(obj, path) {
                if (!obj || typeof obj !== 'object') return;
                for (var k in obj) {
                    var cur = path ? path + '.' + k : k;
                    var v = obj[k];
                    if (typeof v === 'string') {
                        if (k.toLowerCase().indexOf('url') !== -1 ||
                            k.toLowerCase().indexOf('link') !== -1 ||
                            k.toLowerCase().indexOf('inquiry') !== -1 ||
                            v.indexOf('http') === 0) {
                            links.push({ path: cur, url: v });
                        }
                    } else if (typeof v === 'object') { find(v, cur); }
                }
            };
            find(data, '');
        } catch(e) {
            var m = text.match(/https?:\/\/[^\s"'<>]+/g);
            if (m) for (var i = 0; i < m.length; i++) links.push({ path: 'match_' + i, url: m[i] });
        }
        return links;
    }
    var _fetch = window.fetch;
    window.fetch = async function() {
        var args = Array.prototype.slice.call(arguments);
        var url = typeof args[0] === 'string' ? args[0] : (args[0] instanceof Request ? args[0].url : String(args[0]));
        var method = ((args[1] && args[1].method) || (args[0] instanceof Request ? args[0].method : 'GET')).toUpperCase();
        var res = await _fetch.apply(this, args);
        if (method === 'POST' && url.indexOf(TARGET) !== -1) {
            try {
                var body = await res.clone().text();
                window.__capturedData = { url: url, body: body, links: extractLinks(body) };
            } catch(e) {}
        }
        return res;
    };
    var _open = XMLHttpRequest.prototype.open;
    var _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(m, u) { this._m = m; this._u = u; return _open.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function(b) {
        var self = this;
        if (this._m && this._m.toUpperCase() === 'POST' && this._u && this._u.indexOf(TARGET) !== -1) {
            this.addEventListener('loadend', function() {
                if (self.status >= 200 && self.status < 300) {
                    try { window.__capturedData = { url: self._u, body: self.responseText, links: extractLinks(self.responseText) }; } catch(e) {}
                }
            }, { once: true });
        }
        return _send.apply(this, arguments);
    };
})();
"""

CAMERA_TEXTS = [
    "Continue with camera",
    "Continue with Camera",
    # Другие языки (запасные)
    "Continuar con la camara", "Continuar com camera",
    "Continuer avec la camera", "Mit Kamera fortfahren",
    "Continua con la fotocamera", "Продолжить с камерой",
    "Doorgaan met camera", "Kontynuuj z kamera",
    "Kamerayla devam et", "Lanjutkan dengan kamera",
    "camera", "Camera",
]

ID_TEXTS = [
    "Continue with ID",
    "Continue with Id",
    # Запасной вариант — просто Continue (если нет "with ID")
    "Continue",
    # Другие языки (запасные)
    "Continuar con ID", "Continuar com ID",
    "Continuer avec ID", "Mit Ausweis fortfahren",
    "Continua con ID", "Продолжить с удостоверением",
    "Doorgaan met ID", "Kontynuuj z dowodem",
    "Kimlikle devam et", "Lanjutkan dengan ID",
    "Government ID", "ID document",
]

RESET_TEXTS = [
    "Reset", "Start over", "Try again", "Restart",
    "Restablecer", "Reiniciar", "Reinitialiser",
    "Zurucksetzen", "Reimposta", "Сбросить",
    "Opnieuw", "Zresetuj", "Sifirla", "Atur ulang",
]

CONTINUE_TEXTS = [
    # Основные — для 13+ и других подтверждений
    "Continue", "Continue »", "Continue >",
    # Другие языки
    "Continuar", "Continuer", "Fortfahren",
    "Continua", "Продолжить",
    "Doorgaan", "Kontynuuj", "Devam",
    "Lanjutkan", "Tiep tuc",
    # Без Camera/ID — exclude их в вызове
    "Next", "Proceed", "OK", "Submit",
    "Suivant", "Weiter", "Avanti",
    "Далее", "Вперёд", "Volgende",
]


def click_any_text(page, texts, exclude=None):
    if exclude is None:
        exclude = []
    js = """(args) => {
        var texts = args[0]; var exclude = args[1];
        var els = document.querySelectorAll('button, a, div[role=button], span[role=button]');
        for (var i = 0; i < els.length; i++) {
            var t = els[i].textContent.trim(); var tl = t.toLowerCase();
            var skip = false;
            for (var e = 0; e < exclude.length; e++) { if (tl.indexOf(exclude[e].toLowerCase()) !== -1) { skip = true; break; } }
            if (skip) continue;
            for (var j = 0; j < texts.length; j++) {
                if (t === texts[j] || tl === texts[j].toLowerCase()) { els[i].click(); return texts[j]; }
            }
        }
        for (var i = 0; i < els.length; i++) {
            var t = els[i].textContent.trim(); var tl = t.toLowerCase();
            var skip = false;
            for (var e = 0; e < exclude.length; e++) { if (tl.indexOf(exclude[e].toLowerCase()) !== -1) { skip = true; break; } }
            if (skip) continue;
            for (var j = 0; j < texts.length; j++) {
                if (tl.indexOf(texts[j].toLowerCase()) !== -1) { els[i].click(); return texts[j]; }
            }
        }
        return null;
    }"""
    try:
        return page.evaluate(js, [texts, exclude])
    except Exception:
        return None


def build_url(data):
    if not data:
        return None
    body = data.get("body", "")
    links = data.get("links", [])
    for item in links:
        url = item.get("url", "")
        if "withpersona.com" in url and "inquiry-id=" in url and len(url) > 40:
            return url
    inq = re.search(r'inq_[A-Za-z0-9]+', body)
    tok = re.search(r'"sessionToken"\s*:\s*"([^"]{50,})"', body)
    if not tok:
        tok = re.search(r'"session[_-]?[Tt]oken"\s*:\s*"([^"]{50,})"', body)
    if inq:
        url = "https://inquiry.withpersona.com/verify?inquiry-id=" + inq.group(0)
        if tok:
            url += "&session-token=" + tok.group(1)
        return url
    return None


def get_url_via_api(cookie, method):
    """
    Быстрый метод через прямой API запрос (как в консоли браузера).
    Работает без Playwright, занимает ~2 секунды.
    """
    try:
        url = "https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification"
        body = {
            "generateLink": True,
            "ageEstimation": True,
            "parentVerification": False
        }

        s = requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Content-Type": "application/json;charset=utf-8",
            "Origin": "https://www.roblox.com",
            "Referer": "https://www.roblox.com/my/account#!/info",
        })

        # Шаг 1: Первый запрос без CSRF — получаем токен
        r1 = s.post(url, json=body)
        logging.info("API step1: %d", r1.status_code)

        csrf = r1.headers.get("x-csrf-token")
        logging.info("CSRF: %s", csrf)

        if r1.status_code == 200:
            return _extract_api_url(r1)

        if not csrf:
            return None

        # Шаг 2: Повторяем с CSRF токеном
        s.headers["x-csrf-token"] = csrf
        r2 = s.post(url, json=body)
        logging.info("API step2: %d %s", r2.status_code, r2.text[:200])

        if r2.status_code == 200:
            return _extract_api_url(r2)

        return None

    except Exception as e:
        logging.error("API error: %s", e)
        return None


TWO_FA_JS = """
(async () => {
  const url  = 'https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification';
  const body = JSON.stringify({ generateLink: true, ageEstimation: true, parentVerification: false });

  const send = (csrf) => fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json;charset=utf-8',
      ...(csrf ? { 'x-csrf-token': csrf } : {}),
    },
    body,
  });

  let r = await send(null);
  const csrf = r.headers.get('x-csrf-token');
  console.log('1st:', r.status, 'csrf:', csrf);

  if (csrf) r = await send(csrf);

  const text = await r.text();
  console.log('2nd:', r.status);
  try { console.log(JSON.parse(text)); } catch { console.log(text); }

  // Store result for Python to pick up
  try {
    const parsed = JSON.parse(text);
    window.__2fa_result = parsed;
  } catch {
    window.__2fa_result = { raw: text };
  }
})();
"""


def get_url_via_api_2fa(cookie, method):
    """
    2FA без Playwright — curl_cffi имитирует TLS fingerprint Chrome.
    25 параллельных async запросов → 200+ req/min на Railway без лишней памяти.
    """
    import time as _t
    import json as _json
    import asyncio as _asyncio

    try:
        from curl_cffi.requests import AsyncSession
    except ImportError:
        logging.error("curl_cffi не установлен! pip install curl_cffi")
        return None

    URL = "https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification"
    BODY = '{"generateLink":true,"ageEstimation":true,"parentVerification":false}'
    BATCH_SIZE      = 25    # параллельных запросов за раз → ~200 req/min
    PAUSE_NORMAL    = 0.05  # 50ms между батчами
    PAUSE_2FA_WAIT  = 5.0   # 5 сек — даём пользователю время нажать approve
    PAUSE_429       = 3.0
    DEADLINE        = 600   # 10 минут

    def _get_headers(csrf=None):
        h = {
            "Content-Type": "application/json;charset=utf-8",
            "Origin": "https://www.roblox.com",
            "Referer": "https://www.roblox.com/my/account#!/info",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        }
        if csrf:
            h["x-csrf-token"] = csrf
        return h

    async def _single_request(session, csrf):
        try:
            r = await session.post(
                URL,
                data=BODY,
                headers=_get_headers(csrf),
                timeout=15,
                impersonate="chrome124",
            )
            new_csrf = r.headers.get("x-csrf-token")
            challenge_type = r.headers.get("rblx-challenge-type") or ""
            return {
                "status": r.status_code,
                "body": r.text,
                "csrf": new_csrf,
                "challengeType": challenge_type,
            }
        except Exception as e:
            return {"status": 0, "body": str(e), "csrf": None, "challengeType": ""}

    async def _run():
        csrf = None
        total_requests = 0
        iteration = 0
        start = _t.time()

        async with AsyncSession() as session:
            # Шаг 1: получаем CSRF токен
            r0 = await session.post(
                URL, data=BODY,
                headers=_get_headers(None),
                timeout=15,
                impersonate="chrome124",
            )
            csrf = r0.headers.get("x-csrf-token")
            logging.info("2FA curl_cffi: got CSRF=%s status=%d", csrf, r0.status_code)

            if not csrf:
                logging.error("2FA: не получили CSRF, выходим")
                return None

            # Основной цикл
            while _t.time() - start < DEADLINE:
                iteration += 1

                tasks = [_single_request(session, csrf) for _ in range(BATCH_SIZE)]
                results = await _asyncio.gather(*tasks)
                total_requests += len(results)

                elapsed = _t.time() - start
                rps = total_requests / elapsed if elapsed > 0 else 0
                logging.info(
                    "2FA batch#%d | total=%d | ~%.0f req/min | statuses=%s",
                    iteration, total_requests, rps * 60,
                    [r["status"] for r in results]
                )

                got_429 = False
                got_2fa = False
                link = None

                for r in results:
                    # Обновляем CSRF если пришёл новый
                    if r.get("csrf"):
                        csrf = r["csrf"]

                    status = r["status"]
                    body   = r["body"]
                    ctype  = r["challengeType"]

                    if status == 200:
                        logging.info("2FA: status=200 body=%s", body[:500])
                        try:
                            link = extract_link_from_api(_json.loads(body))
                        except Exception:
                            link = None
                        link = link or extract_link_from_raw(body)
                        if link:
                            logging.info("2FA: LINK FOUND: %s", link)
                            return link

                    elif status == 429:
                        got_429 = True

                    elif status == 403 and ctype:
                        # Любой challenge-type (TwoStepVerification, twostep, и т.д.)
                        got_2fa = True

                    elif status == 403 and not ctype:
                        # Обычный 403 без challenge — просто продолжаем
                        pass

                if got_2fa:
                    logging.info("2FA: ждём подтверждения от юзера...")
                    await _asyncio.sleep(PAUSE_2FA_WAIT)
                elif got_429:
                    logging.warning("2FA: 429 rate limit, пауза %ss", PAUSE_429)
                    await _asyncio.sleep(PAUSE_429)
                else:
                    await _asyncio.sleep(PAUSE_NORMAL)

        return None

    try:
        return _asyncio.run(_run())
    except Exception as e:
        logging.error("2FA curl_cffi error: %s", e)
        return None


def _extract_api_url(response):
    """Извлекаем ссылку из ответа API — ищем любой https URL в JSON"""
    try:
        raw = response.text
        logging.info("FULL API response [%d]: %s", response.status_code, raw[:500])

        data = response.json()

        def find_in_obj(obj):
            if isinstance(obj, str):
                if "withpersona.com" in obj or "persona.com" in obj:
                    return obj
                if obj.startswith("https://") and ("verify" in obj or "inquiry" in obj or "inq_" in obj):
                    return obj
            elif isinstance(obj, dict):
                # Приоритетные поля
                for key in ("verificationUrl", "redirectUrl", "url", "personaUrl",
                            "sessionUrl", "inquiryUrl", "link", "verifyUrl"):
                    val = obj.get(key)
                    if val and isinstance(val, str) and val.startswith("http"):
                        logging.info("Found link in key '%s': %s", key, val)
                        return val
                # Рекурсивно по всем полям
                for v in obj.values():
                    r = find_in_obj(v)
                    if r:
                        return r
                # Собираем inquiry-id + session-token
                inq_id = obj.get("inquiryId") or obj.get("inquiry_id") or obj.get("inqId")
                if inq_id:
                    token = obj.get("sessionToken") or obj.get("session_token") or obj.get("token") or ""
                    link = "https://inquiry.withpersona.com/verify?inquiry-id=" + str(inq_id)
                    if token:
                        link += "&session-token=" + str(token)
                    logging.info("Built link from inquiryId: %s", link)
                    return link
            elif isinstance(obj, list):
                for item in obj:
                    r = find_in_obj(item)
                    if r:
                        return r
            return None

        return find_in_obj(data)

    except Exception as e:
        logging.error("Extract error: %s | raw: %s", e, response.text[:300])
        return None



def get_link_via_api(cookie, method):
    """
    Быстрый способ через прямой API запрос (как в консольном скрипте).
    Не требует браузера. Работает без 2FA если cookie валидный.
    """
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
        body = {
            "generateLink": True,
            "ageEstimation": True,
            "parentVerification": False
        }

        # Шаг 1: Первый запрос без CSRF — получаем токен
        r1 = s.post(url, json=body)
        csrf = r1.headers.get("x-csrf-token") or r1.headers.get("X-CSRF-Token")
        logging.info("API step1: %d csrf=%s", r1.status_code, csrf)

        if r1.status_code == 200:
            logging.info("API step1 body: %s", r1.text[:500])
            try:
                link = extract_link_from_api(r1.json())
            except Exception:
                link = None
            link = link or extract_link_from_raw(r1.text)
            if link:
                return link

        # Шаг 2: Повтор с CSRF токеном
        if csrf:
            s.headers["x-csrf-token"] = csrf
            r2 = s.post(url, json=body)
            logging.info("API step2: %d body: %s", r2.status_code, r2.text[:500])
            if r2.status_code == 200:
                try:
                    link = extract_link_from_api(r2.json())
                except Exception:
                    link = None
                link = link or extract_link_from_raw(r2.text)
                if link:
                    return link

        return None
    except Exception as e:
        logging.error("API error: %s", e)
        return None


def extract_link_from_api(data):
    """Ищем ссылку в JSON ответе"""
    if not isinstance(data, dict):
        return None

    # Прямые поля
    for key in ["verificationUrl", "redirectUrl", "url", "link",
                "personaUrl", "inquiryUrl", "sessionUrl", "verifyUrl",
                "sessionUrl", "inquiryLink", "personaLink"]:
        val = data.get(key, "")
        if val and isinstance(val, str) and val.startswith("http"):
            if "withpersona.com" in val or "persona.com" in val:
                return val

    # Строим из inquiry-id если есть
    inq_id = (data.get("inquiryId") or data.get("inquiry_id")
              or data.get("sessionIdentifier") or data.get("inqId"))
    session_token = (data.get("sessionToken") or data.get("session_token")
                     or data.get("sessionKey"))

    if inq_id and str(inq_id).startswith("inq_"):
        link = "https://inquiry.withpersona.com/verify?inquiry-id=" + str(inq_id)
        if session_token:
            link += "&session-token=" + str(session_token)
        return link

    # Ищем рекурсивно по всему дереву
    def find_deep(obj):
        if isinstance(obj, str):
            if ("withpersona.com" in obj or "persona.com" in obj) and obj.startswith("http"):
                return obj
            return None
        if isinstance(obj, dict):
            # Сначала проверяем приоритетные ключи
            for k, v in obj.items():
                if isinstance(v, str) and v.startswith("http"):
                    if "withpersona.com" in v or "persona.com" in v:
                        return v
                # Собираем inq_ из любого поля
                if isinstance(v, str) and v.startswith("inq_") and len(v) > 10:
                    tok = obj.get("sessionToken") or obj.get("session_token") or ""
                    lnk = "https://inquiry.withpersona.com/verify?inquiry-id=" + v
                    if tok:
                        lnk += "&session-token=" + tok
                    return lnk
            for v in obj.values():
                r = find_deep(v)
                if r:
                    return r
        elif isinstance(obj, list):
            for item in obj:
                r = find_deep(item)
                if r:
                    return r
        return None

    return find_deep(data)


def extract_link_from_raw(body: str):
    """
    Запасной парсинг — ищем ссылку прямо в сырой строке тела ответа.
    Срабатывает если JSON не распарсился или ссылка вшита как строка.
    """
    if not body:
        return None

    # Ищем готовую ссылку withpersona.com
    m = re.search(r'https://[^\s"\'\\]+withpersona\.com[^\s"\'\\]*inquiry-id=[^\s"\'\\&]+(?:&[^\s"\'\\]*)?', body)
    if m:
        return m.group(0).rstrip("\\")

    # Ищем inquiry-id= в любом виде
    m = re.search(r'inquiry-id=(inq_[A-Za-z0-9]+)', body)
    if m:
        inq_id = m.group(1)
        tok_m = re.search(r'session-token=([A-Za-z0-9_\-\.]+)', body)
        link = "https://inquiry.withpersona.com/verify?inquiry-id=" + inq_id
        if tok_m:
            link += "&session-token=" + tok_m.group(1)
        return link

    # Ищем inq_XXXX как значение в JSON
    m = re.search(r'"inq_([A-Za-z0-9]{10,})"', body)
    if m:
        inq_id = "inq_" + m.group(1)
        tok_m = re.search(r'"sessionToken"\s*:\s*"([^"]{20,})"', body)
        if not tok_m:
            tok_m = re.search(r'"session[_-]?[Tt]oken"\s*:\s*"([^"]{20,})"', body)
        link = "https://inquiry.withpersona.com/verify?inquiry-id=" + inq_id
        if tok_m:
            link += "&session-token=" + tok_m.group(1)
        return link

    return None


def playwright_get_url(cookie, method):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800},
            )
            ctx.add_cookies([{"name": ".ROBLOSECURITY", "value": cookie, "domain": ".roblox.com", "path": "/"}])
            page = ctx.new_page()
            page.add_init_script(INJECT_SCRIPT)
            page.goto("https://www.roblox.com/my/account#!/info", wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(3000)

            target_texts = CAMERA_TEXTS if method == "camera" else ID_TEXTS
            exclude_words = ["camera", "id", "passport", "камер", "паспорт"]

            reset_clicked = click_any_text(page, RESET_TEXTS)
            if reset_clicked:
                logging.info("Reset: " + str(reset_clicked))
                page.wait_for_timeout(3000)
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                page.wait_for_timeout(2000)

            clicked = False
            for attempt in range(5):
                result = click_any_text(page, target_texts)
                if result:
                    logging.info("Кнопка: " + str(result))
                    clicked = True
                    break
                page.wait_for_timeout(2000)
                if attempt % 2 == 1:
                    r = click_any_text(page, RESET_TEXTS)
                    if r:
                        page.wait_for_timeout(2000)

            if not clicked:
                browser.close()
                return "NOT_CLICKED"

            page.wait_for_timeout(2000)
            cont = click_any_text(page, CONTINUE_TEXTS, exclude=exclude_words)
            if cont:
                page.wait_for_timeout(1500)

            result_url = None
            for i in range(30):
                page.wait_for_timeout(1000)
                try:
                    raw = page.evaluate("() => window.__capturedData")
                    if raw:
                        result_url = build_url(raw)
                        if result_url:
                            logging.info("Ссылка за " + str(i + 1) + " сек")
                            break
                except Exception:
                    pass
                if i % 3 == 0:
                    click_any_text(page, CONTINUE_TEXTS, exclude=exclude_words)

            browser.close()
            return result_url
    except Exception as e:
        logging.error("Playwright error: %s", e)
        return "ERROR: " + str(e)


# ===== CRYPTOBOT =====

def create_invoice(amount, attempts):
    try:
        r = requests.post(
            "https://pay.crypt.bot/api/createInvoice",
            headers={"Crypto-Pay-API-Token": CRYPTO_BOT_TOKEN},
            json={"asset": "USDT", "amount": str(round(amount, 2)),
                  "description": "Pokupka " + str(attempts) + " popytok", "expires_in": 300}
        )
        data = r.json()
        return data["result"] if data.get("ok") else None
    except Exception as e:
        logging.error("CryptoBot: %s", e)
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





# ===== ЛОГИ =====

import time as _time

async def send_log(bot, user_id, username, method, result, elapsed_sec, success, has_2fa=False, has_sub=False):
    """Отправляем лог в канал — только успехи"""
    if not LOG_CHANNEL_ID:
        return
    if not success:
        return
    try:
        if has_2fa and has_sub:
            cost = "♾️ Подписка"
        elif has_2fa:
            cost = "$1.00"
        else:
            cost = "БЕСПЛАТНО"
        if success:
            header = t(user_id, "log_success")
            service = t(user_id, "service_camera") if method == "camera" else t(user_id, "service_id")
            result_text = t(user_id, "log_result_ok")
        else:
            header = t(user_id, "log_fail")
            service = t(user_id, "service_camera") if method == "camera" else t(user_id, "service_id")
            result_text = str(result)[:50] if result else t(user_id, "log_result_fail")

        uname_part = ("@" + username) if (username and not username.isdigit()) else ""
        result_icon = "✅" if success else "❌"

        msg = (
            header + chr(10) +
            "━━━━━━━━━━━━━━━━━━━━━━" + chr(10) +
            "👤 ID: " + str(user_id) +
            (" | " + uname_part if uname_part else "") + chr(10) +
            "⚙️ Услуга: " + service + chr(10) +
            result_icon + " Результат: " + result_text + chr(10) +
            "⏲️ Время: " + str(round(elapsed_sec)) + " сек" + chr(10) +
            "💳 Сумма: " + cost
        )

        await bot.send_message(
            chat_id=LOG_CHANNEL_ID,
            text=msg
        )
    except Exception as e:
        logging.error("Log channel error: %s", e)


# ===== КЛАВИАТУРЫ =====

def main_menu_kb(user_id=None):
    lang = db_get_lang(user_id) if user_id else "ru"
    T = TEXTS[lang]
    buttons = [
        [InlineKeyboardButton(T["btn_get_link"], callback_data="get_link")],
        [InlineKeyboardButton(T["btn_buy"], callback_data="buy"),
         InlineKeyboardButton(T["btn_promo"], callback_data="promo")],
        [InlineKeyboardButton(T["btn_top"], callback_data="top")],
        [InlineKeyboardButton(T["btn_help"], callback_data="help"),
         InlineKeyboardButton(T["btn_support"], url="https://t.me/dedbed12")],
    ]
    if user_id and user_id in ADMIN_IDS:
        buttons.append([InlineKeyboardButton(T["btn_admin"], callback_data="admin")])
    return InlineKeyboardMarkup(buttons)


def _sub_status_text(user_id):
    """
    Возвращает (attempts_display, sub_status) для главного меню.
    - При активной подписке: attempts_display = "∞", sub_status = оставшееся время
    - Иначе: attempts_display = фактическое число, sub_status = "Нет под."
    """
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
            remaining = (f"{h}h {m}m" if lang == "en" else f"{h}ч {m}мин")
        except Exception:
            remaining = "?"
        return "∞", remaining
    else:
        return str(attempts), ("No sub" if lang == "en" else "Нет под.")


async def show_main_menu(update, context):
    user_id = update.effective_user.id
    attempts_display, sub_status = _sub_status_text(user_id)
    text = (
        t(user_id, "main_menu_title") + chr(10) + chr(10) +
        t(user_id, "main_menu_sub") + chr(10) + chr(10) +
        t(user_id, "main_menu_attempts", attempts=attempts_display, sub_status=sub_status) + chr(10) + chr(10) +
        t(user_id, "main_menu_action")
    )
    kb = main_menu_kb(user_id)
    if update.callback_query:
        await update.callback_query.edit_message_text(text, parse_mode="Markdown", reply_markup=kb)
    else:
        await update.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)


# ===== HANDLERS =====

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    tg = update.effective_user
    username = tg.username or tg.first_name or "Аноним"
    db_upsert_user(user_id, username)
    await show_main_menu(update, context)
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
        await query.edit_message_text(
            TEXTS[lang]["lang_set"],
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(TEXTS[lang]["btn_back"], callback_data="main_menu")
            ]])
        )
        return WAITING_MENU

    if data in ["main_menu", "accept_rules"]:
        await show_main_menu(update, context)
        return WAITING_MENU

    if data == "help":
        await query.edit_message_text(
            t(user_id, "help_text"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]])
        )
        return WAITING_MENU

    if data == "top":
        rows = db_get_top(10)
        medals = ["🥇", "🥈", "🥉"]
        lines = [t(user_id, "top_title")]
        if not rows:
            lines.append(t(user_id, "top_empty"))
        else:
            for i, (uid, uname, spent) in enumerate(rows):
                medal = medals[i] if i < 3 else str(i + 1) + "."
                lines.append(medal + " " + (uname or t(user_id, "anon")) + " - $" + str(round(spent, 2)))
        await query.edit_message_text(
            chr(10).join(lines), parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]])
        )
        return WAITING_MENU

    if data == "promo":
        context.user_data["waiting"] = "promo"
        await query.edit_message_text(
            t(user_id, "promo_title") + chr(10) + chr(10) + t(user_id, "promo_enter"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]])
        )
        return WAITING_PROMO

    if data == "buy":
        await query.edit_message_text(
            t(user_id, "buy_title") + chr(10) + chr(10) +
            t(user_id, "buy_price") + chr(10) + chr(10) +
            t(user_id, "buy_discount"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_buy_attempts"), callback_data="buy_attempts")],
                [InlineKeyboardButton(t(user_id, "btn_buy_sub"), callback_data="buy_sub")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")],
            ])
        )
        return WAITING_BUY

    if data == "buy_attempts":
        await query.edit_message_text(
            ("*🎯 Покупка попыток 2FA*" if db_get_lang(user_id) == "ru" else "*🎯 Buy 2FA Attempts*") +
            chr(10) + chr(10) +
            ("Цена: *$1.00* за попытку" if db_get_lang(user_id) == "ru" else "Price: *$1.00* per attempt"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_buy_1"),  callback_data="buy_1")],
                [InlineKeyboardButton(t(user_id, "btn_buy_5"),  callback_data="buy_5")],
                [InlineKeyboardButton(t(user_id, "btn_buy_10"), callback_data="buy_10")],
                [InlineKeyboardButton(t(user_id, "btn_buy_15"), callback_data="buy_15")],
                [InlineKeyboardButton(t(user_id, "btn_buy_25"), callback_data="buy_25")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy")],
            ])
        )
        return WAITING_BUY

    if data == "buy_sub":
        is_active, expires, is_forever = db_get_subscription(user_id)
        if is_active and is_forever:
            sub_line = t(user_id, "sub_active_forever")
        elif is_active:
            import datetime
            try:
                exp = datetime.datetime.fromisoformat(expires)
                exp_str = exp.strftime("%d.%m.%Y %H:%M")
            except Exception:
                exp_str = "?"
            sub_line = t(user_id, "sub_active", expires=exp_str)
        else:
            sub_line = t(user_id, "sub_none")
        await query.edit_message_text(
            ("*♾️ Подписка — безлимит 2FA*" if db_get_lang(user_id) == "ru" else "*♾️ Subscription — unlimited 2FA*") +
            chr(10) + chr(10) + sub_line + chr(10) + chr(10) +
            ("Активная подписка продлевается!" if db_get_lang(user_id) == "ru" else "Active subscription gets extended!"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_sub_1d"),  callback_data="sub_1")],
                [InlineKeyboardButton(t(user_id, "btn_sub_3d"),  callback_data="sub_3")],
                [InlineKeyboardButton(t(user_id, "btn_sub_7d"),  callback_data="sub_7")],
                [InlineKeyboardButton(t(user_id, "btn_sub_30d"), callback_data="sub_30")],
                [InlineKeyboardButton(t(user_id, "btn_sub_inf"), callback_data="sub_0")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy")],
            ])
        )
        return WAITING_BUY

    # Подписка — создаём инвойс
    if data.startswith("sub_") and data[4:].isdigit():
        days = int(data[4:])
        price = SUBSCRIPTIONS.get(days)
        if price is None:
            return WAITING_BUY
        if days == 0:
            desc = t(user_id, "btn_sub_inf")
        else:
            labels = {1: t(user_id, "btn_sub_1d"), 3: t(user_id, "btn_sub_3d"),
                      7: t(user_id, "btn_sub_7d"), 30: t(user_id, "btn_sub_30d")}
            desc = labels.get(days, str(days) + " дней")
        invoice = create_invoice(price, 1)
        if not invoice:
            await query.answer(t(user_id, "pay_error"), show_alert=True)
            return WAITING_BUY
        inv_key = "sub_" + str(user_id) + "_" + str(invoice["invoice_id"])
        pending_payments[inv_key] = {"type": "sub", "days": days, "price": price, "desc": desc}
        await query.edit_message_text(
            ("*Счёт на подписку*" if db_get_lang(user_id) == "ru" else "*Subscription Invoice*") +
            chr(10) + chr(10) +
            desc + chr(10) +
            "Сумма: *$" + str(price) + "*" + chr(10) + chr(10) +
            ("Оплати и нажми Проверить:" if db_get_lang(user_id) == "ru" else "Pay and press Check:"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_pay"), url=invoice["pay_url"])],
                [InlineKeyboardButton(t(user_id, "btn_check_pay"), callback_data="check_" + inv_key)],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="buy_sub")],
            ]),
        )
        return WAITING_PAYMENT

    # Шаг 1 — выбрали кол-во → сразу создаём инвойс CryptoBot
    if data.startswith("buy_") and not data.startswith("buy_pay_") and not data.startswith("buy_attempts") and not data.startswith("buy_sub"):
        count    = int(data.split("_")[1])
        discount = DISCOUNTS_2FA.get(count, 0)
        total    = round(count * PRICE_2FA * (1 - discount), 2)
        await query.edit_message_text(t(user_id, "creating_invoice"))

        raw = create_invoice(total, count)
        invoice = {"invoice_id": str(raw["invoice_id"]), "pay_url": raw["pay_url"]} if raw else None

        if not invoice:
            await query.edit_message_text(
                t(user_id, "pay_error"),
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data=f"buy_{count}")]]),
            )
            return WAITING_MENU

        inv_key = f"cb_{invoice['invoice_id']}"
        pending_payments[inv_key] = {"user_id": user_id, "attempts": count, "total": total, "provider": "cb"}
        await query.edit_message_text(
            t(user_id, "invoice_created", amount=f"${total:.2f}", attempts=count),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_pay"), url=invoice["pay_url"])],
                [InlineKeyboardButton(t(user_id, "btn_check_pay"), callback_data=f"check_{inv_key}")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data=f"buy")],
            ]),
        )
        return WAITING_PAYMENT

    # Проверка оплаты
    if data.startswith("check_"):
        inv_key = data[6:]
        payment = pending_payments.get(inv_key, {})
        raw_id  = "_".join(inv_key.split("_")[1:])   # убираем префикс cb_

        inv  = check_invoice(raw_id)
        paid = bool(inv and inv.get("status") == "paid")

        if paid:
            payment = pending_payments.pop(inv_key, None)
            if payment:
                ptype = payment.get("type", "attempts")
                if ptype == "sub":
                    days = payment["days"]
                    desc = payment.get("desc", "")
                    price = payment.get("price", 0)
                    db_set_subscription(user_id, days)
                    db_upsert_user(user_id, username, spent_delta=price)
                    await query.edit_message_text(
                        t(user_id, "sub_bought", desc=desc),
                        parse_mode="Markdown",
                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]),
                    )
                else:
                    cnt          = payment["attempts"]
                    total        = payment.get("total", cnt * PRICE_2FA)
                    db_upsert_user(user_id, username, attempts_delta=cnt, spent_delta=total)
                    new_attempts = db_get_attempts(user_id)
                    await query.edit_message_text(
                        t(user_id, "pay_ok", attempts=cnt, total=new_attempts),
                        parse_mode="Markdown",
                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]]),
                    )
            else:
                await query.answer("Already processed!" if db_get_lang(user_id) == "en" else "Уже обработано!", show_alert=True)
        else:
            await query.answer(t(user_id, "pay_pending"), show_alert=True)
        return WAITING_MENU

    if data == "get_link":
        # Шаг 1 — спрашиваем про 2FA (без проверки попыток — без 2FA бесплатно)
        await query.edit_message_text(
            t(user_id, "ask_2fa"),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_no_2fa"), callback_data="2fa_no"),
                 InlineKeyboardButton(t(user_id, "btn_with_2fa"), callback_data="2fa_yes")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")],
            ])
        )
        return WAITING_MENU

    if data == "2fa_yes":
        # Шаг 2 — выбор метода (Camera / ID) для 2FA аккаунта
        await query.edit_message_text(
            t(user_id, "choose_method"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_camera"), callback_data="choose_camera_2fa")],
                [InlineKeyboardButton(t(user_id, "btn_id"), callback_data="choose_id_2fa")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="get_link")],
            ])
        )
        return WAITING_MENU

    if data in ["choose_camera_2fa", "choose_id_2fa"]:
        method = "camera" if data == "choose_camera_2fa" else "id"
        context.user_data["method"] = method
        context.user_data["has_2fa"] = True
        method_name = t(user_id, "method_camera") if method == "camera" else t(user_id, "method_id")
        await query.edit_message_text(
            t(user_id, "2fa_ask_cookie"),
            parse_mode="Markdown"
        )
        return WAITING_COOKIE

    if data == "2fa_no":
        # Шаг 2 — выбор метода (Camera / ID)
        await query.edit_message_text(
            t(user_id, "choose_method"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(t(user_id, "btn_camera"), callback_data="choose_camera")],
                [InlineKeyboardButton(t(user_id, "btn_id"), callback_data="choose_id")],
                [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="get_link")],
            ])
        )
        return WAITING_MENU

    if data in ["choose_camera", "choose_id"]:
        method = "camera" if data == "choose_camera" else "id"
        context.user_data["method"] = method
        method_name = t(user_id, "method_camera") if method == "camera" else t(user_id, "method_id")
        await query.edit_message_text(
            "Method: *" + method_name + "*\n\nSend your `.ROBLOSECURITY` cookie\nMessage will be deleted automatically"
            if db_get_lang(user_id) == "en" else
            "Метод: *" + method_name + "*\n\nОтправь `.ROBLOSECURITY` cookie\nСообщение будет удалено автоматически",
            parse_mode="Markdown"
        )
        return WAITING_COOKIE

    # ===== АДМИН =====

    if data == "admin":
        if user_id not in ADMIN_IDS:
            await query.answer("Нет доступа!", show_alert=True)
            return WAITING_MENU
        all_users = db_get_all_users()
        total_users = len(all_users)
        total_attempts = sum(r[2] for r in all_users)
        total_spent = sum(r[3] for r in all_users)
        promos = db_get_all_promos()
        await query.edit_message_text(
            "*Админ панель*" + chr(10) + chr(10) +
            "Пользователей: *" + str(total_users) + "*" + chr(10) +
            "Всего попыток: *" + str(total_attempts) + "*" + chr(10) +
            "Всего продаж: *$" + str(round(total_spent, 2)) + "*" + chr(10) +
            "Промокодов: *" + str(len(promos)) + "*",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔗 Бесплатная ссылка", callback_data="admin_free_link")],
                [InlineKeyboardButton("Рассылка", callback_data="admin_broadcast")],
                [InlineKeyboardButton("Добавить баланс", callback_data="admin_balance")],
                [InlineKeyboardButton("🎫 Управление подпиской", callback_data="admin_sub")],
                [InlineKeyboardButton("Создать промокод", callback_data="admin_promo")],
                [InlineKeyboardButton("Список промокодов", callback_data="admin_promo_list")],
                [InlineKeyboardButton("🔍 Поиск промокода", callback_data="admin_promo_search")],
                [InlineKeyboardButton("Список пользователей", callback_data="admin_users")],
                [InlineKeyboardButton("🔢 Фильтр по попыткам", callback_data="admin_filter_users")],
                [InlineKeyboardButton("Назад", callback_data="main_menu")],
            ])
        )
        return WAITING_ADMIN

    if data == "admin_users":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        rows = db_get_all_users()
        if not rows:
            text = "*Пользователей нет*"
        else:
            lines = ["*Пользователи* (топ 20 по тратам)" + chr(10)]
            for uid, uname, atts, spent in rows[:20]:
                lines.append(
                    "ID: `" + str(uid) + "` | " + (uname or "?") +
                    " | попыток: " + str(atts) +
                    " | $" + str(round(spent, 2))
                )
            text = chr(10).join(lines)
        if len(text) > 4000:
            text = text[:4000] + "..."
        await query.edit_message_text(
            text, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]])
        )
        return WAITING_ADMIN

    if data == "admin_broadcast":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "broadcast"
        await query.edit_message_text(
            "*Рассылка*" + chr(10) + chr(10) + "Напишите текст рассылки:",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]])
        )
        return WAITING_ADMIN_BROADCAST

    if data == "admin_balance":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "add_balance_id"
        await query.edit_message_text(
            "*Добавить баланс*" + chr(10) + chr(10) + "Введите Telegram ID пользователя:",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]])
        )
        return WAITING_ADMIN_ADD_BALANCE

    if data == "admin_promo":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "create_promo"
        await query.edit_message_text(
            "*Создать промокод*" + chr(10) + chr(10) +
            "Формат: `КОД ПОПЫТКИ ИСПОЛЬЗОВАНИЙ`" + chr(10) + chr(10) +
            "Примеры:" + chr(10) +
            "`SUMMER 5 10` - 5 попыток, 10 раз" + chr(10) +
            "`VIP 25 1` - 25 попыток, 1 раз" + chr(10) +
            "`FREE 1 100` - 1 попытка, 100 раз",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]])
        )
        return WAITING_ADMIN_CREATE_PROMO

    if data == "admin_promo_list":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        rows = db_get_all_promos()
        if not rows:
            text = "*Промокодов нет*"
        else:
            lines = ["*Список промокодов*" + chr(10)]
            for code, atts, uses, max_uses in rows:
                lines.append("`" + code + "` - " + str(atts) + " поп. | " + str(uses) + "/" + str(max_uses))
            text = chr(10).join(lines)
        await query.edit_message_text(
            text, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]])
        )
        return WAITING_ADMIN

    # ── Поиск промокода ──────────────────────────────────────────────────────
    if data == "admin_promo_search":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "search_promo"
        await query.edit_message_text(
            "*🔍 Поиск промокода*\n\nВведите часть кода или точный код:",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]])
        )
        return WAITING_ADMIN_SEARCH_PROMO

    # ── Удалить промокод ─────────────────────────────────────────────────────
    if data.startswith("del_promo_"):
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        code_to_del = data[10:]
        db_delete_promo(code_to_del)
        await query.edit_message_text(
            "✅ Промокод `" + code_to_del + "` удалён.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]])
        )
        return WAITING_ADMIN

    # ── Фильтр пользователей по попыткам ────────────────────────────────────
    if data == "admin_filter_users":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "filter_users"
        await query.edit_message_text(
            "*🔢 Фильтр по попыткам*\n\nВведите минимальное количество попыток (например: `5`):",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]])
        )
        return WAITING_ADMIN_FILTER_USERS

    # ── Управление подпиской пользователя ───────────────────────────────────
    if data == "admin_sub":
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["waiting"] = "admin_sub_id"
        await query.edit_message_text(
            "*🎫 Управление подпиской*\n\nВведите Telegram ID пользователя:",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]])
        )
        return WAITING_ADMIN_ADD_SUB

    if data.startswith("admin_give_sub_"):
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        # format: admin_give_sub_<target_id>_<days>
        parts = data.split("_")
        # parts: ['admin','give','sub', target_id, days]
        try:
            target_id = int(parts[3])
            days = int(parts[4])
        except (IndexError, ValueError):
            await query.answer("Ошибка параметров", show_alert=True)
            return WAITING_ADMIN
        db_set_subscription(target_id, days)
        row = db_get_user(target_id)
        tname = row[0] if row else str(target_id)
        desc = "Навсегда" if days == 0 else str(days) + " дн."
        await query.edit_message_text(
            "✅ Подписка выдана!\n\nПользователь: `" + str(target_id) + "` (" + tname + ")\nПериод: *" + desc + "*",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]])
        )
        try:
            await update.get_bot().send_message(
                chat_id=target_id,
                text="🎫 Вам выдана подписка!\nПериод: *" + desc + "*",
                parse_mode="Markdown"
            )
        except Exception:
            pass
        return WAITING_ADMIN

    if data.startswith("admin_revoke_sub_"):
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        try:
            target_id = int(data[len("admin_revoke_sub_"):])
        except ValueError:
            await query.answer("Ошибка", show_alert=True)
            return WAITING_ADMIN
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM subscriptions WHERE user_id=?", (target_id,))
        conn.commit()
        conn.close()
        await query.edit_message_text(
            "✅ Подписка пользователя `" + str(target_id) + "` отозвана.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]])
        )
        return WAITING_ADMIN

    # ===== БЕСПЛАТНАЯ ССЫЛКА (только для админа) =====
    if data == "admin_free_link":
        if user_id not in ADMIN_IDS:
            await query.answer("Нет доступа!", show_alert=True)
            return WAITING_MENU
        await query.edit_message_text(
            "*🔗 Бесплатная ссылка*\n\nВыберите тип аккаунта:",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔓 Без 2FA (быстро ~2 сек)", callback_data="admin_free_no2fa")],
                [InlineKeyboardButton("🔐 С 2FA (до 10 мин)", callback_data="admin_free_2fa")],
                [InlineKeyboardButton("Назад", callback_data="admin")],
            ])
        )
        return WAITING_ADMIN

    if data in ["admin_free_no2fa", "admin_free_2fa"]:
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["admin_free_mode"] = True
        context.user_data["has_2fa"] = (data == "admin_free_2fa")
        await query.edit_message_text(
            "*🔗 Бесплатная ссылка*\n\nВыберите метод:",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📷 Camera", callback_data="admin_free_cam")],
                [InlineKeyboardButton("🪪 ID", callback_data="admin_free_id")],
                [InlineKeyboardButton("Назад", callback_data="admin_free_link")],
            ])
        )
        return WAITING_ADMIN

    if data in ["admin_free_cam", "admin_free_id"]:
        if user_id not in ADMIN_IDS:
            return WAITING_MENU
        context.user_data["method"] = "camera" if data == "admin_free_cam" else "id"
        mode = "С 2FA" if context.user_data.get("has_2fa") else "Без 2FA"
        await query.edit_message_text(
            "*🔗 Бесплатная ссылка*\n\nРежим: *" + mode + "*\nМетод: *" +
            ("Camera" if data == "admin_free_cam" else "ID") + "*\n\n" +
            "Отправь `.ROBLOSECURITY` cookie\n_(сообщение удалится автоматически)_",
            parse_mode="Markdown"
        )
        return WAITING_ADMIN

    return WAITING_MENU


async def receive_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    user_id = update.effective_user.id
    tg = update.effective_user
    username = tg.username or tg.first_name or "Аноним"
    waiting = context.user_data.get("waiting")

    if waiting == "promo":
        context.user_data["waiting"] = None
        code_upper = text.upper()
        ok, msg_key, atts = db_use_promo(user_id, code_upper)
        if ok:
            db_upsert_user(user_id, username, attempts_delta=atts)
            new_attempts = db_get_attempts(user_id)
            await update.message.reply_text(
                t(user_id, "promo_ok", attempts=atts, total=new_attempts),
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]])
            )
        else:
            # msg_key is one of: "Промокод не найден!", "Промокод уже использован!", "Вы уже использовали этот промокод!"
            if "не найден" in msg_key or "not found" in msg_key:
                reply_msg = t(user_id, "promo_not_found")
            elif "уже использован" in msg_key and "Вы" not in msg_key:
                reply_msg = t(user_id, "promo_used")
            else:
                reply_msg = t(user_id, "promo_used_by_you")
            await update.message.reply_text(
                reply_msg,
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")]])
            )
        return WAITING_MENU

    if waiting == "broadcast" and user_id in ADMIN_IDS:
        context.user_data["waiting"] = None
        rows = db_get_all_users()
        sent = 0
        failed = 0
        for row in rows:
            try:
                await update.get_bot().send_message(chat_id=row[0], text=text, parse_mode="Markdown")
                sent += 1
            except Exception:
                failed += 1
        await update.message.reply_text(
            "*Рассылка завершена*" + chr(10) + "Отправлено: " + str(sent) + chr(10) + "Ошибок: " + str(failed),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("В админку", callback_data="admin")]])
        )
        return WAITING_ADMIN

    if waiting == "add_balance_id" and user_id in ADMIN_IDS:
        try:
            target_id = int(text)
            context.user_data["target_id"] = target_id
            context.user_data["waiting"] = "add_balance_amount"
            await update.message.reply_text(
                "ID: *" + str(target_id) + "*" + chr(10) + chr(10) + "Введите количество попыток:",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="admin")]])
            )
            return WAITING_ADMIN_ADD_BALANCE_AMOUNT
        except ValueError:
            await update.message.reply_text("Неверный ID!")
            return WAITING_ADMIN_ADD_BALANCE

    if waiting == "add_balance_amount" and user_id in ADMIN_IDS:
        context.user_data["waiting"] = None
        target_id = context.user_data.get("target_id")
        try:
            amount = int(text)
            row = db_get_user(target_id)
            target_name = row[0] if row else "Пользователь"
            db_upsert_user(target_id, target_name, attempts_delta=amount)
            new_atts = db_get_attempts(target_id)
            await update.message.reply_text(
                "*Баланс пополнен!*" + chr(10) +
                "ID: `" + str(target_id) + "`" + chr(10) +
                "Добавлено: *" + str(amount) + "* попыток" + chr(10) +
                "Итого: *" + str(new_atts) + "*",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("В админку", callback_data="admin")]])
            )
            try:
                await update.get_bot().send_message(
                    chat_id=target_id,
                    text="Вам начислено *" + str(amount) + "* попыток! Всего: *" + str(new_atts) + "*",
                    parse_mode="Markdown"
                )
            except Exception:
                pass
        except ValueError:
            await update.message.reply_text("Неверное количество!")
        return WAITING_ADMIN

    if waiting == "search_promo" and user_id in ADMIN_IDS:
        context.user_data["waiting"] = None
        results = db_search_promos(text.strip())
        if not results:
            reply_text = "🔍 Промокодов по запросу *" + text.strip() + "* не найдено."
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]])
        else:
            lines = ["*🔍 Результаты поиска: " + text.strip() + "*" + chr(10)]
            buttons = []
            for code, atts, uses, max_uses in results:
                lines.append("`" + code + "` — " + str(atts) + " поп. | " + str(uses) + "/" + str(max_uses))
                buttons.append([InlineKeyboardButton("🗑 Удалить " + code, callback_data="del_promo_" + code)])
            buttons.append([InlineKeyboardButton("Назад", callback_data="admin")])
            reply_text = chr(10).join(lines)
            kb = InlineKeyboardMarkup(buttons)
        await update.message.reply_text(reply_text, parse_mode="Markdown", reply_markup=kb)
        return WAITING_ADMIN

    if waiting == "filter_users" and user_id in ADMIN_IDS:
        context.user_data["waiting"] = None
        try:
            min_att = int(text.strip())
        except ValueError:
            await update.message.reply_text(
                "Неверное значение! Введите число.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]])
            )
            return WAITING_ADMIN
        rows = db_filter_users_by_attempts(min_att)
        if not rows:
            reply_text = "Пользователей с ≥ " + str(min_att) + " попытками не найдено."
        else:
            lines = ["*Пользователи с ≥ " + str(min_att) + " попытками* (" + str(len(rows)) + " чел.)" + chr(10)]
            for uid, uname, atts, spent in rows[:30]:
                lines.append("ID: `" + str(uid) + "` | " + (uname or "?") +
                              " | " + str(atts) + " поп. | $" + str(round(spent, 2)))
            if len(rows) > 30:
                lines.append("_... и ещё " + str(len(rows) - 30) + " пользователей_")
            reply_text = chr(10).join(lines)
        if len(reply_text) > 4000:
            reply_text = reply_text[:4000] + "..."
        await update.message.reply_text(
            reply_text, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]])
        )
        return WAITING_ADMIN

    if waiting == "admin_sub_id" and user_id in ADMIN_IDS:
        try:
            target_id = int(text.strip())
            context.user_data["admin_sub_target"] = target_id
            context.user_data["waiting"] = None
        except ValueError:
            await update.message.reply_text(
                "Неверный ID!",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Назад", callback_data="admin")]])
            )
            return WAITING_ADMIN_ADD_SUB
        row = db_get_user(target_id)
        tname = row[0] if row else str(target_id)
        is_active, expires, is_forever = db_get_subscription(target_id)
        if is_active and is_forever:
            sub_line = "♾️ Навсегда"
        elif is_active:
            sub_line = "до " + str(expires)[:16]
        else:
            sub_line = "нет подписки"
        await update.message.reply_text(
            "*🎫 Подписка пользователя*\n\n"
            "ID: `" + str(target_id) + "` (" + tname + ")\n"
            "Статус: " + sub_line + "\n\n"
            "Выберите действие:",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📅 +1 день",    callback_data="admin_give_sub_" + str(target_id) + "_1")],
                [InlineKeyboardButton("📅 +3 дня",    callback_data="admin_give_sub_" + str(target_id) + "_3")],
                [InlineKeyboardButton("📅 +7 дней",   callback_data="admin_give_sub_" + str(target_id) + "_7")],
                [InlineKeyboardButton("📅 +30 дней",  callback_data="admin_give_sub_" + str(target_id) + "_30")],
                [InlineKeyboardButton("♾️ Навсегда",  callback_data="admin_give_sub_" + str(target_id) + "_0")],
                [InlineKeyboardButton("❌ Отозвать",   callback_data="admin_revoke_sub_" + str(target_id))],
                [InlineKeyboardButton("Назад",         callback_data="admin")],
            ])
        )
        return WAITING_ADMIN_ADD_SUB

    if waiting == "create_promo" and user_id in ADMIN_IDS:
        context.user_data["waiting"] = None
        parts = text.strip().split()
        if not parts:
            await update.message.reply_text("Неверный формат! Пример: `SUMMER 5 10`", parse_mode="Markdown")
            context.user_data["waiting"] = "create_promo"
            return WAITING_ADMIN_CREATE_PROMO
        new_code = parts[0].upper()
        try:
            atts = max(1, min(int(parts[1]) if len(parts) > 1 else 1, 1000))
        except Exception:
            atts = 1
        try:
            max_uses = max(1, min(int(parts[2]) if len(parts) > 2 else 1, 10000))
        except Exception:
            max_uses = 1
        db_create_promo(new_code, atts, max_uses)
        await update.message.reply_text(
            "✅ *Промокод создан*" + chr(10) +
            "━━━━━━━━━━━━━━━━━━━━━━" + chr(10) +
            "Код: `" + new_code + "`" + chr(10) +
            "Сумма: *" + str(atts) + "* попыток" + chr(10) +
            "Лимит: *" + str(max_uses) + "*" + chr(10) +
            "Срок: ∞ дней",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("В админку", callback_data="admin")]])
        )
        return WAITING_ADMIN

    # Бесплатная ссылка для админа — без списания и без лога
    if context.user_data.get("admin_free_mode") and user_id in ADMIN_IDS:
        context.user_data["admin_free_mode"] = False
        cookie = text
        method = context.user_data.get("method", "camera")
        has_2fa = context.user_data.get("has_2fa", False)
        try:
            await update.message.delete()
        except Exception:
            pass
        msg = await update.message.reply_text("⏳ Получаю ссылку...")
        s = requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        r = s.get("https://users.roblox.com/v1/users/authenticated")
        if r.status_code != 200:
            await msg.edit_text("❌ Невалидный cookie!")
            return WAITING_ADMIN
        roblox_user = r.json()
        await msg.edit_text("✅ *" + roblox_user["name"] + "*\n⏳ Получаю ссылку...", parse_mode="Markdown")
        loop = asyncio.get_event_loop()
        _start = _time.time()
        if has_2fa:
            result = await loop.run_in_executor(executor, call_worker_2fa, cookie, method)
        else:
            result = await loop.run_in_executor(executor, get_link_via_api, cookie, method)
            if not result:
                result = await loop.run_in_executor(executor, playwright_get_url, cookie, method)
        elapsed = round(_time.time() - _start)
        if result and "withpersona.com" in result:
            await msg.edit_text("✅ *Ссылка за " + str(elapsed) + " сек!*", parse_mode="Markdown")
            await update.message.reply_text(result)
        else:
            await msg.edit_text("❌ Не удалось (" + str(elapsed) + " сек)")
        context.user_data["has_2fa"] = False
        context.user_data["method"] = None
        return WAITING_ADMIN

    return await receive_cookie(update, context)


async def receive_cookie(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cookie = update.message.text.strip()
    method = context.user_data.get("method")
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

    # ── Автоматический чекер 2FA ──────────────────────────────────────────────
    auto_2fa = False
    try:
        r2fa = s.get("https://twostepverification.roblox.com/v1/metadata")
        if r2fa.status_code == 200:
            meta = r2fa.json()
            methods = meta.get("enabledMethods", []) or []
            auto_2fa = len(methods) > 0
            logging.info("2FA check: status=%d methods=%s auto_2fa=%s", r2fa.status_code, methods, auto_2fa)
    except Exception as e:
        logging.warning("2FA check error: %s", e)

    # Используем ТОЛЬКО выбор пользователя — без override через auto_2fa.
    # auto_2fa логируем для отладки, но на тарификацию он не влияет.
    # Если юзер выбрал "Без 2FA" → бесплатно, даже если на аккаунте есть 2FA методы.
    has_2fa = context.user_data.get("has_2fa", False)
    logging.info("has_2fa=%s (user_choice=%s auto_detected=%s)", has_2fa, has_2fa, auto_2fa)

    # ── Проверка баланса / подписки ───────────────────────────────────────────
    if has_2fa:
        # Проверяем подписку
        is_sub_active, _, _ = db_get_subscription(user_id)
        if not is_sub_active:
            # Проверяем попытки 2FA
            attempts = db_get_attempts(user_id)
            if attempts <= 0:
                lang = db_get_lang(user_id)
                no_bal_text = (
                    "❌ *Нет попыток 2FA!*\n\n"
                    "Купи попытки или подписку безлимит:"
                    if lang == "ru" else
                    "❌ *No 2FA attempts!*\n\nBuy attempts or unlimited subscription:"
                )
                await msg.edit_text(
                    no_bal_text,
                    parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup([
                        [InlineKeyboardButton(t(user_id, "btn_buy_attempts"), callback_data="buy_attempts")],
                        [InlineKeyboardButton(t(user_id, "btn_buy_sub"), callback_data="buy_sub")],
                        [InlineKeyboardButton(t(user_id, "btn_back"), callback_data="main_menu")],
                    ])
                )
                return WAITING_MENU
            # Списываем одну попытку 2FA
            db_upsert_user(user_id, username, attempts_delta=-1, spent_delta=PRICE_2FA)
        else:
            logging.info("2FA: подписка активна — попытка не списывается")
    # Если без 2FA — БЕСПЛАТНО, ничего не списываем

    loop = asyncio.get_event_loop()
    _start_time = _time.time()

    if has_2fa:
        processing_text = (
            "Аккаунт: *{name}*\nМетод: *{method}*\nОсталось попыток: *{attempts}*\n\n⚡ 2FA режим - Пытаюсь получить ссылку"
            if db_get_lang(user_id) == "ru" else
            "Account: *{name}*\nMethod: *{method}*\nAttempts left: *{attempts}*\n\n⚡ 2FA mode - Trying to get link"
        ).format(name=user["name"], method=method_name, attempts=db_get_attempts(user_id))
    else:
        processing_text = t(user_id, "processing", name=user["name"], method=method_name, attempts=db_get_attempts(user_id))

    await msg.edit_text(processing_text, parse_mode="Markdown")

    if has_2fa:
        # Отправляем на воркер (отдельный Railway аккаунт)
        result = await loop.run_in_executor(executor, call_worker_2fa, cookie, method)
        logging.info("2FA worker result: %s", result)
    else:
        # Сначала быстрый API метод (~2 сек) — используем полный парсер
        result = await loop.run_in_executor(executor, get_link_via_api, cookie, method)
        logging.info("API result: %s", result)

        # Если API не сработал — используем Playwright (~30 сек)
        if not result:
            await msg.edit_text(t(user_id, "browser_fallback"))
            result = await loop.run_in_executor(executor, playwright_get_url, cookie, method)

    elapsed = round(_time.time() - _start_time)

    if result and "withpersona.com" in result:
        # Успех
        await msg.edit_text(t(user_id, "link_received"), parse_mode="Markdown")
        await update.message.reply_text(result)
        _sub_active, _, _ = db_get_subscription(user_id)
        await send_log(update.get_bot(), user_id, username, method, t(user_id, "log_result_ok"), elapsed, True, has_2fa=has_2fa, has_sub=_sub_active)
        context.user_data["has_2fa"] = False
        _at, _ss = _sub_status_text(user_id)
        await update.message.reply_text(
            t(user_id, "main_menu_title") + chr(10) + chr(10) +
            t(user_id, "main_menu_attempts", attempts=_at, sub_status=_ss) + chr(10) + chr(10) +
            t(user_id, "main_menu_action"),
            parse_mode="Markdown",
            reply_markup=main_menu_kb(user_id)
        )
        return WAITING_MENU

    # Неудача — возвращаем попытку только если это была 2FA без подписки
    if has_2fa:
        is_sub_active, _, _ = db_get_subscription(user_id)
        if not is_sub_active:
            db_upsert_user(user_id, username, attempts_delta=1, spent_delta=-PRICE_2FA)
    await send_log(update.get_bot(), user_id, username, method, t(user_id, "log_result_fail"), elapsed, False)

    if has_2fa:
        # Для 2FA: сразу снова запрашиваем cookie, не уходим в меню
        method_name = t(user_id, "method_camera") if method == "camera" else t(user_id, "method_id")
        retry_text = (
            "❌ Не удалось — попытка возвращена!\n\n"
            "Метод: *{method}*\n\nОтправь cookie снова:"
            if db_get_lang(user_id) == "ru" else
            "❌ Failed — attempt returned!\n\n"
            "Method: *{method}*\n\nSend cookie again:"
        ).format(method=method_name)
        await msg.edit_text(retry_text, parse_mode="Markdown")
        # has_2fa и method остаются в context.user_data — сразу ждём cookie
        return WAITING_COOKIE
    else:
        if isinstance(result, str) and result.startswith("ERROR"):
            err = result[7:200]
            await msg.edit_text(t(user_id, "error_returned", reason=err))
        elif result == "NOT_CLICKED":
            await msg.edit_text(t(user_id, "not_clicked_returned"))
        else:
            await msg.edit_text(t(user_id, "failed_returned"))

        _at, _ss = _sub_status_text(user_id)
        await update.message.reply_text(
            t(user_id, "main_menu_title") + chr(10) + chr(10) +
            t(user_id, "main_menu_attempts", attempts=_at, sub_status=_ss) + chr(10) + chr(10) +
            t(user_id, "main_menu_action"),
            parse_mode="Markdown",
            reply_markup=main_menu_kb(user_id)
        )
        return WAITING_MENU


async def lan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    await update.message.reply_text(
        TEXTS["ru"]["lang_choose"],
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🇷🇺 Русский", callback_data="set_lang_ru"),
             InlineKeyboardButton("🇬🇧 English", callback_data="set_lang_en")]
        ])
    )
    return WAITING_MENU


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    await update.message.reply_text(t(user_id, "cancelled"))
    return ConversationHandler.END


def main():
    db_init()
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    conv = ConversationHandler(
        entry_points=[CommandHandler("start", start), CommandHandler("lan", lan_command)],
        states={
            WAITING_RULES:                  [CallbackQueryHandler(handle_callback)],
            WAITING_MENU:                   [CallbackQueryHandler(handle_callback)],
            WAITING_COOKIE:                 [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_BUY:                    [CallbackQueryHandler(handle_callback)],
            WAITING_PAYMENT:                [CallbackQueryHandler(handle_callback)],
            WAITING_PROMO:                  [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN:                  [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN_BROADCAST:        [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN_ADD_BALANCE:      [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN_ADD_BALANCE_AMOUNT:[CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN_CREATE_PROMO:     [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN_ADD_SUB:          [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN_ADD_SUB_DAYS:     [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN_FILTER_USERS:     [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
            WAITING_ADMIN_SEARCH_PROMO:     [CallbackQueryHandler(handle_callback),
                                             MessageHandler(filters.TEXT & ~filters.COMMAND, receive_text)],
        },
        fallbacks=[CommandHandler("cancel", cancel), CommandHandler("start", start), CommandHandler("lan", lan_command)],
        per_user=True,
        per_chat=True,
        block=False,
    )
    app.add_handler(conv)
    print("Bot started!")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()