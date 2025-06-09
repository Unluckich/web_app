import os
import logging
import asyncio
from flask import Flask, render_template, request, redirect, url_for, abort, make_response
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from telegram import Bot
from base64 import b64decode

# =================== НАЛАШТУВАННЯ ===================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "7888461204:AAEf1X2YtlV4-DMc6A5LQuQAqMU7bTJ4Tdg")
ADMIN_USER_IDS = [797316319]
# ======================================================

app = Flask(__name__)
# Генеруємо зовнішні URL із правильним доменом
app.config.update({
    "PREFERRED_URL_SCHEME": "https",
    "SERVER_NAME": "web-app-d8fd.onrender.com"
})

app.logger.setLevel(logging.INFO)

# Ініціалізуємо Telegram Bot API (асинхронний Bot v20+)
bot = Bot(token=TELEGRAM_BOT_TOKEN)


def load_private_key():
    """Завантажує приватний ключ із файла (PKCS#8)."""
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key


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

    app.logger.info(f"Розшифрований текст: {plain_text}")

    sent_count = 0
    for admin_id in ADMIN_USER_IDS:
        try:
            asyncio.run(bot.send_message(chat_id=admin_id, text=f"📧 Повідомлення з форми: {plain_text}"))
            app.logger.info(f"Відправлено адміну {admin_id}")
            sent_count += 1
        except Exception as e:
            app.logger.error(f"Не вдалося надіслати адміну {admin_id}: {e}")

    app.logger.info(f"Повідомлення було розшифровано та надіслано {sent_count} адміністраторам.")

    # Редірект на зовнішній URL thank_you
    return redirect(url_for("thank_you", _external=True))


@app.route("/thankyou", methods=["GET"])
def thank_you():
    html = """
    <html>
      <head>
        <meta charset="utf-8">
        <title>Дякуємо!</title>
      </head>
      <body>
        <h2>Дякуємо, ваше повідомлення успішно надіслано.</h2>
        <p>Ми отримаємо його і якнайшвидше відповімо.</p>
      </body>
    </html>
    """
    return make_response(html)


if __name__ == "__main__":
    # Render керує HTTPS/SSL та портом через ENV PORT — запускаємо звичайний HTTP
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)