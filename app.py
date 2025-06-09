import os
import logging
import threading
import asyncio
from queue import Queue, Empty
from flask import Flask, render_template, request, redirect, url_for, abort, make_response
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64decode
from telegram import Bot
from telegram.request import HTTPXRequest
from asyncio import run_coroutine_threadsafe
import time

# ============ НАЛАШТУВАННЯ ============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")

TELEGRAM_BOT_TOKEN = "7888461204:AAEf1X2YtlV4-DMc6A5LQuQAqMU7bTJ4Tdg"
ADMIN_USER_IDS = [797316319]
# ======================================

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Telegram Bot з пулом з’єднань
request = HTTPXRequest(connection_pool_size=10)
bot = Bot(token=TELEGRAM_BOT_TOKEN, request=request)

# Event loop для Telegram-бота
bot_loop = asyncio.new_event_loop()

# Черга повідомлень
message_queue = Queue()


@app.before_first_request
def startup():
    """Запускає event loop і воркер для черги повідомлень."""
    threading.Thread(target=bot_loop.run_forever, daemon=True).start()
    threading.Thread(target=telegram_worker, daemon=True).start()


def telegram_worker():
    """Постійно обробляє чергу повідомлень і надсилає їх ботом."""
    while True:
        try:
            chat_id, text = message_queue.get(timeout=1)
            future = run_coroutine_threadsafe(
                bot.send_message(chat_id=chat_id, text=text),
                bot_loop
            )
            future.result(timeout=10)
            app.logger.info(f"✅ Надіслано повідомлення до {chat_id}")
        except Empty:
            continue  # Немає нових повідомлень
        except Exception as e:
            app.logger.error(f"❌ Помилка надсилання повідомлення: {e}")
        finally:
            time.sleep(0.1)  # Щоб не перевантажувати CPU


def load_private_key():
    """Завантажує приватний ключ."""
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)


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
        app.logger.error(f"Помилка декодування base64: {e}")
        abort(400, description="Некоректне кодування повідомлення.")

    try:
        decrypted = load_private_key().decrypt(encrypted_bytes, padding.PKCS1v15())
        plain_text = decrypted.decode("utf-8")
    except Exception as e:
        app.logger.error(f"Помилка розшифровки: {e}")
        abort(400, description="Не вдалося розшифрувати повідомлення.")

    app.logger.info(f"Розшифрований текст: {plain_text}")

    for admin_id in ADMIN_USER_IDS:
        message_queue.put((admin_id, f"📧 Повідомлення з форми:\n\n{plain_text}"))

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

