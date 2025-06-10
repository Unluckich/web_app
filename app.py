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

# =================== НАЛАШТУВАННЯ ===================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")
FERNET_KEY_PATH = os.path.join(KEYS_DIR, "fernet.key")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "7888461204:AAEf1X2YtlV4-DMc6A5LQuQAqMU7bTJ4Tdg")
ADMIN_USER_IDS = [797316319]

# Redis settings
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
QUEUE_KEY = "telegram_queue"
# ======================================================

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Підключення до Redis
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

# Завантаження/генерація ключа Fernet для внутрішнього шифрування черги

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

# Ініціалізуємо Telegram Bot API (асинхронний Bot)
bot = Bot(token=TELEGRAM_BOT_TOKEN)
bot_loop = asyncio.new_event_loop()

# =================== Функції ===================

def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(), password=None
        )

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
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
    except Exception as e:
        app.logger.error(f"Помилка dekodування base64: {e}")
        abort(400, description="Неможливо розшифрувати повідомлення (некоректний формат).")

    private_key = load_private_key()
    try:
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.PKCS1v15()
        )
        plain_text = decrypted.decode("utf-8")
    except Exception as e:
        app.logger.error(f"Помилка розшифровки: {e}")
        abort(400, description="Не вдалося розшифрувати повідомлення.")

    # Шифруємо текст для Redis-черги
    payload = plain_text.encode('utf-8')
    encrypted_payload = fernet.encrypt(payload)
    redis_client.lpush(QUEUE_KEY, encrypted_payload)
    app.logger.info("Повідомлення зашифровано і додано в Redis-чергу.")

    return redirect(url_for("thank_you"))

@app.route("/thankyou", methods=["GET"])
def thank_you():
    html = """
    <html>
      <head><meta charset="utf-8"><title>Дякуємо!</title></head>
      <body>
        <h2>Дякуємо, ваше повідомлення успішно надіслано.</h2>
        <p>Ми отримаємо його і якнайшвидше відповімо.</p>
      </body>
    </html>
    """
    return make_response(html)

# Фоновий воркер для обробки Redis-черги
def telegram_worker():
    while True:
        try:
            item = redis_client.brpop(QUEUE_KEY, timeout=1)
            if not item:
                continue
            _, encrypted_payload = item
            # Дешифруємо перед відправкою
            text = fernet.decrypt(encrypted_payload).decode('utf-8')

            for admin_id in ADMIN_USER_IDS:
                future = run_coroutine_threadsafe(
                    bot.send_message(chat_id=admin_id, text=f"📧 Повідомлення з форми:\n\n{text}"),
                    bot_loop
                )
                future.result(timeout=10)
                app.logger.info(f"✅ Надіслано повідомлення до {admin_id}")
        except Exception as e:
            app.logger.error(f"❌ Помилка обробки Redis-черги: {e}")
        finally:
            time.sleep(0.1)

# Запуск бекграундних потоків
def start_background_threads():
    threading.Thread(target=bot_loop.run_forever, daemon=True).start()
    threading.Thread(target=telegram_worker, daemon=True).start()

if __name__ == "__main__":
    start_background_threads()
    app.run(host="0.0.0.0", port=5000, debug=True)