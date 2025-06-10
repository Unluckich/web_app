import os
import logging
import asyncio
import threading
import time
import redis
from flask import Flask, render_template, request, redirect, url_for, abort, make_response
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from telegram import Bot
from base64 import b64decode
from asyncio import run_coroutine_threadsafe

# ================ НАЛАШТУВАННЯ ===================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")
FERNET_KEY_PATH = os.path.join(KEYS_DIR, "fernet.key")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN is not set in environment variables")

ADMIN_USER_IDS = [int(uid) for uid in os.getenv("ADMIN_USER_IDS", "").split(",") if uid]

# Redis settings
REDIS_URL = os.getenv("REDIS_URL")
redis_client = None

def init_redis():
    global redis_client
    try:
        if REDIS_URL:
            redis_client = redis.from_url(REDIS_URL, decode_responses=False)
            redis_client.ping()
            logging.info("✅ Connected to Redis via REDIS_URL.")
        else:
            logging.warning("⚠️ REDIS_URL not set, Redis will not be used.")
    except Exception as e:
        logging.error(f"❌ Failed to connect to Redis: {e}")
        redis_client = None

init_redis()
QUEUE_KEY = "telegram_queue"
# ===================================================

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Load or generate Fernet key
def load_fernet_key():
    if not os.path.exists(FERNET_KEY_PATH):
        key = Fernet.generate_key()
        with open(FERNET_KEY_PATH, "wb") as f:
            f.write(key)
    else:
        with open(FERNET_KEY_PATH, "rb") as f:
            key = f.read()
    return key

fernet = Fernet(load_fernet_key())

# Initialize Telegram Bot
bot = Bot(token=TELEGRAM_BOT_TOKEN)
bot_loop = asyncio.new_event_loop()

# =================== Helpers ===================
def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(), password=None
        )

@app.after_request
def add_no_cache_headers(response):
    response.headers.update({
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0"
    })
    return response

@app.route("/report", methods=["GET"])
def report_form():
    try:
        with open(PUBLIC_KEY_PATH, "r") as f:
            public_pem = f.read()
    except FileNotFoundError:
        abort(500, description="Публічний ключ не знайдено на сервері.")
    return render_template("report.html", public_key=public_pem)

@app.route("/submit", methods=["POST"])
def submit_report():
    encrypted_b64 = request.form.get("encrypted_message")
    if not encrypted_b64:
        abort(400, description="Не надійшло поле encrypted_message.")

    try:
        encrypted_bytes = b64decode(encrypted_b64)
        private_key = load_private_key()
        decrypted = private_key.decrypt(encrypted_bytes, padding.PKCS1v15())
        plain_text = decrypted.decode("utf-8")
    except Exception as e:
        app.logger.error(f"Помилка розшифровки: {e}")
        abort(400, description="Не вдалося розшифрувати повідомлення.")

    if not redis_client:
        app.logger.warning("Redis недоступний, повідомлення не збережено.")
        abort(503, description="Сервіс тимчасово недоступний (немає Redis).")

    try:
        encrypted_payload = fernet.encrypt(plain_text.encode('utf-8'))
        redis_client.lpush(QUEUE_KEY, encrypted_payload)
        app.logger.info("📥 Повідомлення додано в Redis-чергу.")
    except Exception as e:
        app.logger.error(f"❌ Помилка запису в Redis: {e}")
        abort(500, description="Помилка внутрішнього сервісу.")

    return redirect(url_for("thank_you"))

@app.route("/thankyou", methods=["GET"])
def thank_you():
    html = ("""
    <html><head><meta charset="utf-8"><title>Дякуємо!</title></head><body>
      <h2>Дякуємо, ваше повідомлення успішно надіслано.</h2>
      <p>Ми отримаємо його і якнайшвидше відповімо.</p>
    </body></html>
    """)
    return make_response(html)

# =================== ВОРКЕР ===================
def telegram_worker():
    global redis_client
    if not redis_client:
        app.logger.warning("Redis недоступний. Worker не запущений.")
        return

    app.logger.info("👷‍♂️ Telegram worker запущено.")
    while True:
        try:
            item = redis_client.brpop(QUEUE_KEY, timeout=5)
            if not item:
                continue
            _, encrypted_payload = item
            text = fernet.decrypt(encrypted_payload).decode('utf-8')
            for admin_id in ADMIN_USER_IDS:
                future = run_coroutine_threadsafe(
                    bot.send_message(chat_id=admin_id, text=f"📧 Повідомлення з форми:\n\n{text}"),
                    bot_loop
                )
                future.result(timeout=10)
                app.logger.info(f"✅ Надіслано до {admin_id}")
        except Exception as e:
            app.logger.error(f"❌ Worker помилка: {e}")
        time.sleep(0.1)

# =================== СТАРТ ===================
if __name__ == "__main__":
    threading.Thread(target=bot_loop.run_forever, daemon=True).start()
    if redis_client:
        threading.Thread(target=telegram_worker, daemon=True).start()
    else:
        app.logger.warning("⚠️ Redis не ініціалізований. Воркери не запущено.")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
