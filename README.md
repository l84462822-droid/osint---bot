# OSINT Utility Telegram Bot

Небольшой Telegram-бот для проверки публичной технической информации об инфраструктуре, очистки метаданных изображений и проверки собственного email в Have I Been Pwned.

## Возможности

- `/domain example.org` — публичные DNS-записи A, AAAA, MX, NS и TXT.
- `/ip 8.8.8.8` — определение типа IP-адреса и его опубликованной обратной DNS-записи (PTR).
- `/url https://example.org/path` — разбор URL и DNS домена; бот не загружает страницу.
- `/breach your_email@example.com` — после явного подтверждения проверка email через Have I Been Pwned API v3. Проверка разрешена только в личном чате. Используйте только свой адрес. Email передаётся сервису HIBP; бот не записывает его или ответ в файл/базу и не показывает пароли.
- Отправка изображения — пересохранение JPEG/PNG/WebP без встроенных метаданных (например, EXIF).

Для `/breach` необходим отдельный API-ключ HIBP. Отсутствие результата не является гарантией, что адрес никогда не попадал в утечки. Бот не ищет людей по номеру автомобиля, лицу, фото, телефону или нику.

## Запуск

Требуется Python 3.10+, токен Telegram-бота от `@BotFather` и (для проверки утечек) API-ключ на [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key).

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN="токен_от_BotFather"
export HIBP_API_KEY="ключ_HIBP"
python bot.py
```

PowerShell:

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
$env:TELEGRAM_BOT_TOKEN="токен_от_BotFather"
$env:HIBP_API_KEY="ключ_HIBP"
python bot.py
```

Не публикуйте токены и API-ключи в репозитории и не отправляйте их в чат. Храните их в переменных окружения на своём компьютере/сервере.
