import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import time
from io import BytesIO
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

import dns.resolver
from PIL import Image, UnidentifiedImageError
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_IMAGE_BYTES = 10 * 1024 * 1024
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=true"


def normalized_host(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Укажите домен или URL.")
    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = parsed.hostname
    if not host:
        raise ValueError("Не удалось определить домен.")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.rstrip(".").encode("idna").decode("ascii").lower()
    if len(host) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        host,
    ):
        raise ValueError("Неверный формат домена.")
    return host


def lookup_dns(host: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for record_type in DNS_TYPES:
        try:
            answers = dns.resolver.resolve(host, record_type, lifetime=3)
            result[record_type] = [str(answer).strip('"') for answer in answers]
        except Exception:
            result[record_type] = []
    return result


def format_domain_report(host: str, records: dict[str, list[str]]) -> str:
    lines = [f"Публичная DNS-сводка: {host}"]
    for record_type, values in records.items():
        lines.append(f"{record_type}: " + (", ".join(values[:5]) if values else "не найдено"))
    lines.append("\nЭто техническая сводка DNS, а не идентификация владельца домена.")
    return "\n".join(lines)


def query_hibp(email: str, api_key: str) -> list[dict]:
    """Query HIBP v3; never log the email, request URL, or API key."""
    url = HIBP_URL.format(quote(email, safe=""))
    request = Request(
        url,
        headers={
            "hibp-api-key": api_key,
            "user-agent": "osint---bot/1.0 (personal email breach check)",
            "accept": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            payload = response.read(2_000_000)
            decoded = json.loads(payload.decode("utf-8"))
            if not isinstance(decoded, list):
                raise RuntimeError("unexpected_response")
            return decoded
    except HTTPError as exc:
        if exc.code == 404:
            return []
        if exc.code in (401, 403):
            raise RuntimeError("api_key") from None
        if exc.code == 429:
            raise RuntimeError("rate_limit") from None
        if exc.code == 400:
            raise RuntimeError("invalid_request") from None
        raise RuntimeError("service_error") from None
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        raise RuntimeError("connection_error") from None


def start_text() -> str:
    return (
        "Привет! Я бот для безопасной проверки публичной технической информации и очистки метаданных изображений.\n"
        "Команды: /domain <домен>, /ip <IP>, /url <URL>, /breach <ваш_email>, /help.\n"
        "Для проверки утечек используется Have I Been Pwned; перед запросом бот попросит подтверждение."
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(start_text())


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "/domain example.org — публичные DNS-записи (A, AAAA, MX, NS, TXT)\n"
        "/ip 8.8.8.8 — тип IP и опубликованная обратная DNS-запись\n"
        "/url https://example.org/path — разбор URL и DNS без открытия сайта\n"
        "/breach you@example.com — проверка вашего email в Have I Been Pwned; требуется API-ключ и подтверждение\n"
        "Фото/изображение — пересохранение без встроенных метаданных.\n\n"
        "Проверяйте только принадлежащий вам email. Адрес передаётся Have I Been Pwned для поиска и временно хранится в памяти бота до подтверждения (не записывается в базу/файл).\n"
        "Бот не ищет личность по номеру машины, лицу, фото, телефону или нику и не показывает пароли."
    )


async def domain_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        host = normalized_host(" ".join(context.args))
        try:
            ipaddress.ip_address(host)
            await update.message.reply_text("Это IP-адрес. Используйте команду /ip.")
            return
        except ValueError:
            pass
        records = await asyncio.to_thread(lookup_dns, host)
        await update.message.reply_text(format_domain_report(host, records))
    except ValueError as exc:
        await update.message.reply_text(str(exc))


async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    raw = " ".join(context.args).strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        await update.message.reply_text("Укажите корректный IPv4 или IPv6 адрес, например: /ip 8.8.8.8")
        return

    lines = [
        f"IP: {address}",
        f"Версия: IPv{address.version}",
        f"Глобально маршрутизируемый: {'да' if address.is_global else 'нет'}",
    ]
    if address.is_global:
        try:
            ptr = await asyncio.to_thread(socket.gethostbyaddr, str(address))
            lines.append(f"Обратная DNS-запись (PTR): {ptr[0]}")
        except Exception:
            lines.append("Обратная DNS-запись (PTR): не опубликована")
    else:
        lines.append("Частный/служебный адрес — публичная обратная DNS-проверка не выполнялась.")
    lines.append("\nГеолокация и личность владельца не определяются.")
    await update.message.reply_text("\n".join(lines))


async def url_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    raw = " ".join(context.args).strip()
    try:
        host = normalized_host(raw)
        parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
        scheme = parsed.scheme or "https"
        if scheme not in ("http", "https"):
            await update.message.reply_text("Поддерживаются только URL с http или https.")
            return
        records = await asyncio.to_thread(lookup_dns, host)
        lines = [f"Схема: {scheme}", f"Домен: {host}", f"Путь: {parsed.path or '/'}"]
        lines.extend(
            f"{kind}: " + (", ".join(values[:5]) if values else "не найдено")
            for kind, values in records.items()
            if kind in ("A", "AAAA")
        )
        lines.append("\nСайт не открывался; содержимое и безопасность страницы не проверялись.")
        await update.message.reply_text("\n".join(lines))
    except ValueError as exc:
        await update.message.reply_text(str(exc))


async def breach_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.type != "private":
        await update.message.reply_text("Команда проверки email доступна только в личном чате с ботом.")
        return
    if not os.environ.get("HIBP_API_KEY"):
        await update.message.reply_text(
            "Проверка пока не настроена: владельцу бота нужно задать HIBP_API_KEY. "
            "Ключ можно получить на haveibeenpwned.com/API/Key."
        )
        return
    if len(context.args) != 1:
        await update.message.reply_text("Использование: /breach your_email@example.com — проверяйте только свой адрес.")
        return

    email = context.args[0].strip()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        await update.message.reply_text("Похоже, это некорректный email. Проверьте формат адреса.")
        return

    context.user_data["pending_breach_email"] = email
    context.user_data["pending_breach_at"] = time.time()
    keyboard = InlineKeyboardMarkup(
        [[
            InlineKeyboardButton("Да, это мой email — проверить", callback_data="breach:confirm"),
            InlineKeyboardButton("Отмена", callback_data="breach:cancel"),
        ]]
    )
    await update.message.reply_text(
        f"Проверить {email}? Подтвердите, только если это ваш адрес. После подтверждения email будет передан Have I Been Pwned. Бот не сохраняет его в файл или базу данных.",
        reply_markup=keyboard,
    )


async def breach_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if query.data == "breach:cancel":
        context.user_data.pop("pending_breach_email", None)
        context.user_data.pop("pending_breach_at", None)
        await query.edit_message_text("Проверка отменена.")
        return

    email = context.user_data.pop("pending_breach_email", None)
    requested_at = context.user_data.pop("pending_breach_at", 0)
    if not email or time.time() - requested_at > 300:
        await query.edit_message_text("Подтверждение устарело. Запустите /breach заново.")
        return
    if query.message.chat.type != "private":
        await query.edit_message_text("Проверка доступна только в личном чате с ботом.")
        return

    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        await query.edit_message_text("Проверка не настроена: владелец бота должен задать HIBP_API_KEY.")
        return

    await query.edit_message_text("Проверяю адрес в Have I Been Pwned…")
    try:
        breaches = await asyncio.to_thread(query_hibp, email, api_key)
    except RuntimeError as exc:
        messages = {
            "api_key": "Сервис отклонил API-ключ. Владельцу бота нужно проверить HIBP_API_KEY.",
            "rate_limit": "Достигнут лимит запросов Have I Been Pwned. Попробуйте позже.",
            "invalid_request": "Сервис не принял запрос. Проверьте адрес и повторите позже.",
            "connection_error": "Не удалось подключиться к сервису утечек. Попробуйте позже.",
            "service_error": "Сервис утечек временно вернул ошибку. Попробуйте позже.",
            "unexpected_response": "Сервис вернул неожиданный ответ. Попробуйте позже.",
        }
        await query.message.reply_text(messages.get(str(exc), "Не удалось выполнить проверку."))
        return

    if not breaches:
        await query.message.reply_text(
            "Адрес не найден в доступных публичных утечках Have I Been Pwned. Это не гарантия отсутствия утечек: некоторые инциденты могут быть неизвестны, недоступны или исключены из сервиса."
        )
        return

    lines = [f"Найдено записей об утечках: {len(breaches)}. Ниже только сведения об инцидентах — пароли не запрашиваются и не показываются."]
    for breach in breaches[:12]:
        title = str(breach.get("Title") or breach.get("Name") or "Без названия")[:100]
        date = str(breach.get("BreachDate") or "дата неизвестна")[:20]
        classes = breach.get("DataClasses") or []
        safe_classes = ", ".join(str(item)[:50] for item in classes[:8]) if isinstance(classes, list) else "не указаны"
        lines.append(f"• {title} ({date}); категории: {safe_classes or 'не указаны'}")
    if len(breaches) > 12:
        lines.append(f"…и ещё {len(breaches) - 12} записей.")
    lines.append("\nРекомендации: смените повторно использованные пароли, включите 2FA и будьте осторожны с фишинговыми сообщениями.")
    await query.message.reply_text("\n".join(lines))


async def clean_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.message
    media = message.photo[-1] if message.photo else message.document
    if not media:
        return
    if message.document and message.document.mime_type and not message.document.mime_type.startswith("image/"):
        await message.reply_text("Пришлите изображение, а не другой тип файла.")
        return
    if media.file_size and media.file_size > MAX_IMAGE_BYTES:
        await message.reply_text("Максимальный размер изображения — 10 МБ.")
        return

    try:
        tg_file = await context.bot.get_file(media.file_id)
        raw = BytesIO()
        await tg_file.download_to_memory(out=raw)
        if raw.tell() > MAX_IMAGE_BYTES:
            await message.reply_text("Максимальный размер изображения — 10 МБ.")
            return
        raw.seek(0)
        with Image.open(raw) as image:
            image.load()
            image_format = image.format or "PNG"
            if image_format not in ("JPEG", "PNG", "WEBP"):
                image_format = "PNG"
            if image_format == "JPEG" and image.mode not in ("RGB", "L"):
                image = image.convert("RGB")
            elif image_format == "PNG" and image.mode not in ("RGB", "RGBA", "L", "LA"):
                image = image.convert("RGBA")
            cleaned = BytesIO()
            image.save(cleaned, format=image_format)
            cleaned.seek(0)
            cleaned.name = f"image_without_metadata.{image_format.lower()}"
            await message.reply_document(
                document=cleaned,
                filename=cleaned.name,
                caption=f"Готово: {image.width}×{image.height}. Изображение пересохранено без встроенных метаданных.",
            )
    except (UnidentifiedImageError, OSError):
        await message.reply_text("Не удалось прочитать это изображение. Поддерживаются JPEG, PNG и WebP.")
    except Exception:
        logger.exception("Image processing failed")
        await message.reply_text("Не удалось обработать файл. Попробуйте другое изображение.")


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("Установите переменную окружения TELEGRAM_BOT_TOKEN (см. .env.example).")
    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("domain", domain_command))
    app.add_handler(CommandHandler("ip", ip_command))
    app.add_handler(CommandHandler("url", url_command))
    app.add_handler(CommandHandler("breach", breach_command))
    app.add_handler(CallbackQueryHandler(breach_callback, pattern=r"^breach:(confirm|cancel)$"))
    app.add_handler(MessageHandler(filters.PHOTO | filters.Document.IMAGE, clean_image))
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
