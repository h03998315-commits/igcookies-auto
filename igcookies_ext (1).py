# -*- coding: utf-8 -*-
import os
import requests
import re
import time
import json
from urllib.parse import urljoin

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")

IG_BASE = "https://www.instagram.com"
LOGIN_AJAX = IG_BASE + "/accounts/login/ajax/"
TWO_FACTOR_AJAX = IG_BASE + "/accounts/login/ajax/two_factor/"

COOKIE_SEQUENCE = [
    "mid", "ig_did", "csrftoken", "rur", "ds_user_id", "sessionid",
    "ig_nrcb", "X-MID", "IG-U-DS-USER-ID", "X-IG-WWW-Claim", "ps_l", "ps_n"
]

def clean_cookie_string(cookie: str) -> str:
    cookie = re.sub(r'\s*;\s*', '; ', cookie)
    return cookie.strip('; ').strip()

def cookie_dict_from_session(sess: requests.Session) -> dict:
    return {c.name: c.value for c in sess.cookies}

def build_ordered_cookie_string(cdict: dict) -> str:
    parts = []
    for key in COOKIE_SEQUENCE:
        if key in cdict:
            v = cdict[key]
            if (',' in v or ' ' in v) and not (v.startswith('"') and v.endswith('"')):
                v = f'"{v}"'
            parts.append(f"{key}={v}")
    for k in sorted(cdict.keys()):
        if k not in COOKIE_SEQUENCE:
            v = cdict[k]
            if (',' in v or ' ' in v) and not (v.startswith('"') and v.endswith('"')):
                v = f'"{v}"'
            parts.append(f"{k}={v}")
    return clean_cookie_string('; '.join(parts))

def send_telegram_msg(text: str, chat_id=None, reply_markup=None) -> None:
    target_id = chat_id or TELEGRAM_CHAT_ID
    if not TELEGRAM_BOT_TOKEN or not target_id:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": target_id, "text": text, "parse_mode": "HTML"}
    if reply_markup:
        data["reply_markup"] = json.dumps(reply_markup)
    try:
        requests.post(url, data=data, timeout=15)
    except:
        pass

def _post_challenge_code(session: requests.Session, challenge_path: str, code: str):
    full = urljoin(IG_BASE, challenge_path)
    headers = {"X-CSRFToken": session.cookies.get("csrftoken", ""), "Referer": full}
    payloads = [
        {"security_code": code},
        {"sms_code": code},
        {"verification_code": code},
        {"security_code": code, "choice": "1"},
    ]
    for p in payloads:
        try:
            r = session.post(full, data=p, headers=headers, timeout=20)
            try: return r.json()
            except: return {"status": "unknown", "raw": r.text}
        except: continue
    raise RuntimeError("Failed to submit challenge code")

def instagram_login(username, password, ua, chat_id):
    s = requests.Session()
    s.headers.update({"User-Agent": ua, "X-Requested-With": "XMLHttpRequest", "Referer": IG_BASE + "/accounts/login/"})
    s.get(IG_BASE + "/", timeout=20)
    csrftoken = s.cookies.get("csrftoken", "")
    enc_password = f"#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}"
    login_data = {"username": username, "enc_password": enc_password, "queryParams": "{}", "optIntoOneTap": "false"}
    s.headers.update({"X-CSRFToken": csrftoken})
    r = s.post(LOGIN_AJAX, data=login_data, timeout=20)
    j = r.json()

    if j.get("authenticated"):
        return build_ordered_cookie_string(cookie_dict_from_session(s))

    if j.get("two_factor_required"):
        send_telegram_msg("🔐 2FA Required. Please reply with the code.", chat_id)
        return "2FA_REQUIRED"

    if j.get("challenge_required"):
        send_telegram_msg("✉️ Verification Required. Check Email/SMS.", chat_id)
        return "CHALLENGE_REQUIRED"

    raise RuntimeError(f"Login failed: {j.get('message', 'Unknown error')}")

def get_updates(offset=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
    params = {"timeout": 30, "offset": offset, "allowed_updates": ["message", "callback_query"]}
    try:
        r = requests.get(url, params=params, timeout=35)
        return r.json().get("result", [])
    except:
        return []

def main():
    print("""\033[1;97m
\033[1;94m══════════════════════════════════════════════\033[0m
\033[1;96m     ✦❘༻  \033[1;107;30m  F R O Z E N \033[0m \033[1;96m༺❘✦
\033[1;94m══════════════════════════════════════════════\033[0m

\033[1;90m Owner      : \033[1;91m@DarkFrozenOwner
\033[1;90m Tool       : \033[1;96mInstagram Cookies Extractor Tool
\033[1;90m Channels   : \033[1;94m@DarkFrozenGaming\033[1;37m , \033[1;94m@BlackHatFrozen
\033[1;90m

\033[1;94m══════════════════════════════════════════════
\033[1;96m     ✦❘༻  \033[1;107;30m   F R O Z E N  \033[0m \033[1;96m༺❘✦
\033[1;94m══════════════════════════════════════════════\033[0m
""")
    print("Bot started and listening for commands...")
    offset = None
    user_state = {} # chat_id: state
    
    while True:
        updates = get_updates(offset)
        for update in updates:
            offset = update['update_id'] + 1
            
            # Handle Callback Queries (Buttons)
            if 'callback_query' in update:
                cb = update['callback_query']
                chat_id = cb['message']['chat']['id']
                data = cb.get('data', '')
                
                if data == 'ext_cookies':
                    user_state[chat_id] = 'awaiting_creds'
                    send_telegram_msg("🍪 <b>Cookie Extractor Selected</b>\nPlease send your credentials in format:\n<code>username password</code>", chat_id)
                elif data == 'ig_creator':
                    send_telegram_msg("🛠 <b>IG Creator Selected</b>\nThis feature is currently under development. Stay tuned!", chat_id)
                continue

            if 'message' not in update: continue
            msg = update['message']
            chat_id = msg['chat']['id']
            text = msg.get('text', '')

            if text.startswith('/start'):
                welcome_text = (
                    "<b>✦❘༻ F R O Z E N ༺❘✦</b>\n"
                    "══════════════════════\n"
                    "Welcome! Select an option below:\n"
                    "══════════════════════"
                )
                markup = {
                    "inline_keyboard": [
                        [{"text": "🍪 Cookie Extractor", "callback_data": "ext_cookies"}],
                        [{"text": "🛠 IG Creator", "callback_data": "ig_creator"}]
                    ]
                }
                send_telegram_msg(welcome_text, chat_id, reply_markup=markup)
                user_state[chat_id] = None
                
            elif user_state.get(chat_id) == 'awaiting_creds':
                parts = text.split()
                if len(parts) == 2:
                    user, pw = parts
                    send_telegram_msg(f"⏳ <b>Processing:</b> <code>{user}</code>...", chat_id)
                    try:
                        res = instagram_login(user, pw, DEFAULT_UA, chat_id)
                        if res not in ["2FA_REQUIRED", "CHALLENGE_REQUIRED"]:
                            success_text = (
                                "✅ <b>Login Successful!</b>\n"
                                f"<b>Account:</b> <code>{user}</code>\n"
                                "══════════════════════\n"
                                "<b>Captured Cookies:</b>\n"
                                f"<pre>{res}</pre>\n"
                                "══════════════════════"
                            )
                            send_telegram_msg(success_text, chat_id)
                            user_state[chat_id] = None # Reset state after success
                    except Exception as e:
                        error_text = f"❌ <b>Error:</b>\n<code>{str(e)}</code>"
                        send_telegram_msg(error_text, chat_id)
                else:
                    send_telegram_msg("⚠️ <b>Invalid format.</b>\nUse: <code>username password</code>", chat_id)
            else:
                send_telegram_msg("👋 Please use /start to see available options.", chat_id)
        time.sleep(1)

if __name__ == "__main__":
    main()
