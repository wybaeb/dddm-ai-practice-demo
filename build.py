#!/usr/bin/env python3
"""
build.py — генератор зашифрованной all-in-one страницы для GitHub Pages.

Берёт src/app.html, шифрует его паролем (PBKDF2-HMAC-SHA256 + AES-256-GCM,
совместимо с WebCrypto в браузере) и собирает index.html с парольным гейтом.
После ввода пароля страница расшифровывается на клиенте, пароль кладётся в
localStorage — при следующем заходе пароль не запрашивается.

Использование:
    python3 build.py --password 'ВАШ_ПАРОЛЬ'
    # или
    DDDM_PASSWORD='ВАШ_ПАРОЛЬ' python3 build.py
"""
import argparse, base64, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 200_000
ROOT = os.path.dirname(os.path.abspath(__file__))

def b64(b): return base64.b64encode(b).decode()

def encrypt(plaintext: bytes, password: str):
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER)
    key = kdf.derive(password.encode())
    ct = AESGCM(key).encrypt(iv, plaintext, None)  # ct||tag, совместимо с WebCrypto
    return b64(salt), b64(iv), b64(ct)

GATE = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DDDM · Сквозная практика с ИИ</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
 font-family:-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;
 background:linear-gradient(118deg,#0E9BD8 0%,#2BC0C8 46%,#8DF45C 100%);color:#0e2430}}
.card{{background:#fff;border-radius:22px;box-shadow:0 24px 70px rgba(8,50,72,.32);
 padding:38px 34px;width:min(420px,92vw);text-align:center}}
.mark{{width:46px;height:46px;border-radius:13px;margin:0 auto 16px;
 background:linear-gradient(118deg,#0E9BD8,#2BC0C8 46%,#8DF45C);box-shadow:0 6px 18px rgba(43,192,200,.5)}}
h1{{font-size:21px;margin:0 0 4px}} p{{color:#5a7384;font-size:14px;margin:0 0 22px}}
input{{width:100%;padding:13px 15px;font-size:16px;border:1.5px solid #d7e6ec;border-radius:12px;outline:none;text-align:center}}
input:focus{{border-color:#2BC0C8}}
button{{margin-top:12px;width:100%;padding:13px;font-size:15px;font-weight:700;border:0;border-radius:12px;cursor:pointer;
 background:linear-gradient(118deg,#0E9BD8,#2BC0C8 46%,#7BEC5E);color:#06303f}}
button:hover{{filter:brightness(1.04)}}
.err{{color:#d8623e;font-size:13px;height:18px;margin-top:10px;font-weight:600}}
.foot{{margin-top:18px;font-size:11.5px;color:#9bb0bb}}
.agent{{margin-top:18px;padding-top:16px;border-top:1px solid #e7eef2;text-align:left;font-size:12.5px;color:#5a7384}}
.agent b{{color:#0e2430}}
.agent a{{color:#0A84C2;font-weight:700;word-break:break-all}}
</style></head>
<body>
<div class="card">
 <div class="mark"></div>
 <h1>DDDM · Сквозная практика</h1>
 <p>Демо-набор закрыт паролем. Введите пароль, чтобы открыть.</p>
 <input id="pw" type="password" placeholder="Пароль" autocomplete="current-password" autofocus>
 <button id="go">Открыть</button>
 <div class="err" id="err"></div>
 <!-- Незашифрованная часть: ссылка для ИИ-агента (доступна БЕЗ пароля).
      Агент читает её первой и начинает вести практику по программе репозитория. -->
 <div class="agent">
   <b><svg style="width:1.1em;height:1.1em;vertical-align:-0.2em;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round" viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="9" width="14" height="11" rx="2"/><circle cx="9" cy="14" r="1.5"/><circle cx="15" cy="14" r="1.5"/><path d="M10 18h4"/><path d="M12 4v5"/><circle cx="12" cy="3" r="1.5"/><path d="M3 13h2"/><path d="M19 13h2"/></svg> Для ИИ-агента (без пароля):</b> начните с инструкции
   <a href="https://github.com/wybaeb/dddm-ai-practice-demo/blob/main/AGENT.md">AGENT.md</a>
   — в ней программа практики, правила и ссылки на <code>PROGRAM.md</code> / <code>CHECKLIST.md</code>.
   <br>Raw: <a href="https://raw.githubusercontent.com/wybaeb/dddm-ai-practice-demo/main/AGENT.md">raw AGENT.md</a>
 </div>
 <div class="foot">Пристрелочный демо-набор · v0.1 · агентская инструкция открыта, материалы — под паролем</div>
</div>
<script>
const DATA={{salt:"{salt}",iv:"{iv}",ct:"{ct}",iter:{iter}}};
const KEY="dddm_demo_pw";
const dec=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function unlock(pw){{
  const enc=new TextEncoder();
  const km=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey(
    {{name:"PBKDF2",salt:dec(DATA.salt),iterations:DATA.iter,hash:"SHA-256"}},
    km,{{name:"AES-GCM",length:256}},false,["decrypt"]);
  const pt=await crypto.subtle.decrypt({{name:"AES-GCM",iv:dec(DATA.iv)}},key,dec(DATA.ct));
  return new TextDecoder().decode(pt);
}}
async function render(html){{document.open();document.write(html);document.close();}}
async function attempt(pw,fromCache){{
  try{{const html=await unlock(pw);localStorage.setItem(KEY,pw);await render(html);}}
  catch(e){{if(fromCache){{localStorage.removeItem(KEY);}}else{{
    document.getElementById("err").textContent="Неверный пароль";
    document.getElementById("pw").value="";document.getElementById("pw").focus();}}}}
}}
document.getElementById("go").onclick=()=>attempt(document.getElementById("pw").value,false);
document.getElementById("pw").addEventListener("keydown",e=>{{if(e.key==="Enter")attempt(e.target.value,false);}});
const cached=localStorage.getItem(KEY);
if(cached) attempt(cached,true);
</script>
</body></html>
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--password", default=os.environ.get("DDDM_PASSWORD"))
    ap.add_argument("--src", default=os.path.join(ROOT, "src", "app.html"))
    ap.add_argument("--out", default=os.path.join(ROOT, "index.html"))
    a = ap.parse_args()
    if not a.password:
        sys.exit("Нужен пароль: --password '...' или DDDM_PASSWORD=...")
    with open(a.src, "rb") as f:
        plaintext = f.read()
    salt, iv, ct = encrypt(plaintext, a.password)
    html = GATE.format(salt=salt, iv=iv, ct=ct, iter=ITER)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"OK · {a.out} · payload {len(ct)} b64-chars · iter {ITER}")

if __name__ == "__main__":
    main()
