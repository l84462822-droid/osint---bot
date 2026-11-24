import asyncio
import ipaddress
import logging
import os
import re
from io import BytesIO
from urllib.parse import urlsplit

import dns.resolver
from PIL import Image, UnidentifiedImageError
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_IMAGE_BYTES = 10 * 1024 * 1024
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


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
    if len(host) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
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


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Привет! Я бот для безопасной проверки публичной инфраструктуры и очистки метаданных изображений.\n"
        "Команды: /domain <домен>, /ip <IP>, /url <URL>, /help.\n"
        "Отправьте фото или изображение документом — я удалю его метаданные и верну очищенную копию."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "/domain example.org — публичные DNS-записи (A, AAAA, MX, NS, TXT)\n"
        "/ip 8.8.8.8 — тип адреса и обратная DNS-запись, если она опубликована\n"
        "/url https://example.org/path — разбор адреса и DNS домена без открытия сайта\n"
        "Фото/изображение — удалить EXIF и другие встроенные метаданные.\n\n"
        "Бот не ищет личность по номеру автомобиля, лицу, фото или никнейму и не собирает досье на людей."
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

    lines = [f"IP: {address}", f"Версия: IPv{address.version}", f"Глобально маршрутизируемый: {'да' if address.is_global else 'нет'}"]
    if address.is_global:
        try:
            ptr = await asyncio.to_thread(lambda: __import__("socket").gethostbyaddr(str(address))[0])
            lines.append(f"Обратная DNS-запись (PTR): {ptr}")
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
        lines.extend(f"{kind}: " + (", ".join(values[:5]) if values else "не найдено") for kind, values in records.items() if kind in ("A", "AAAA"))
        lines.append("\nСайт не открывался; содержимое и безопасность страницы не проверялись.")
        await update.message.reply_text("\n".join(lines))
    except ValueError as exc:
        await update.message.reply_text(str(exc))


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
                caption=f"Готово: {image.width}×{image.height}. Изображение пересохранено без встроенных метаданных."
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
    app.add_handler(MessageHandler(filters.PHOTO | filters.Document.IMAGE, clean_image))
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
