import os
import sys
import json
import time
import base64
import asyncio
import threading
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if os.name == 'nt':
    os.system("")

bdr = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
dld = os.path.join(bdr, "downloads")
os.makedirs(dld, exist_ok=True)
cfg = os.path.join(bdr, "config.json")

cbl = "\033[94m"
cgr = "\033[92m"
cre = "\033[91m"
cye = "\033[93m"
ccy = "\033[96m"
cma = "\033[95m"
cwh = "\033[97m"
cbd = "\033[1m"
crs = "\033[0m"

dtc = [cre, cgr, cye, cbl, cma, ccy, cwh]

src = """import asyncio, os, base64, json, secrets
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hkd(slt, mat, inf):
    return HKDF(SHA256(), 32, slt, inf).derive(mat)

def enc(key, dat):
    aes = AESGCM(key)
    iv = os.urandom(12)
    return iv + aes.encrypt(iv, dat, None)

def dec(key, pay):
    try:
        return AESGCM(key).decrypt(pay[:12], pay[12:], None)
    except:
        return None

class nod:
    def __init__(self, rdr, wtr, sky):
        self.r = rdr
        self.w = wtr
        self.sky = sky
        self.sek = None
        self.eph = x25519.X25519PrivateKey.generate()

    async def hsk(self):
        cpb = await self.r.readexactly(32)
        ppb = x25519.X25519PublicKey.from_public_bytes(cpb)
        sh1 = self.sky.exchange(ppb)
        ky1 = hkd(None, sh1, b"NiosHandshake")
        sh2 = self.eph.exchange(ppb)
        self.sek = hkd(None, sh1 + sh2, b"NiosSocket")
        mpb = self.eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.w.write(enc(ky1, mpb))
        await self.w.drain()

    async def snd(self, dat):
        res = enc(self.sek, dat)
        self.w.write(len(res).to_bytes(4, 'big') + res)
        await self.w.drain()

    async def rcv(self):
        lng = int.from_bytes(await self.r.readexactly(4), 'big')
        return dec(self.sek, await self.r.readexactly(lng))

cli = {}

async def con(rdr, wtr, sky):
    nd = nod(rdr, wtr, sky)
    try:
        await nd.hsk()
    except:
        return wtr.close()
    
    sid = secrets.token_hex(3).upper()
    cli[sid] = nd
    print(f"[+] Client connected: {sid}")
    
    try:
        await nd.snd(json.dumps({"type": "system", "text": f"Session ID:{sid}"}).encode())
        while True:
            dat = json.loads(await nd.rcv())
            if dat.get("action") == "send":
                tgt = dat.get("to")
                txt = dat.get("text")
                if tgt in cli:
                    await cli[tgt].snd(json.dumps({"type": "message", "from": sid, "text": txt}).encode())
    except:
        pass
    finally:
        cli.pop(sid, None)
        print(f"[-] Client disconnected: {sid}")
        wtr.close()

async def run():
    sky = x25519.X25519PrivateKey.generate()
    pub = base64.b64encode(sky.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    srv = await asyncio.start_server(lambda r, w: con(r, w, sky), '0.0.0.0', 7234)
    print(f"PORT: 7234\\nACCESS KEY: {pub}\\n")
    async with srv:
        await srv.serve_forever()

if __name__ == '__main__':
    asyncio.run(run())
"""

b64 = base64.b64encode(src.encode()).decode()

def kdf(slt, mat, inf):
    return HKDF(SHA256(), 32, slt, inf).derive(mat)

def enc(key, dat):
    aes = AESGCM(key)
    iv = os.urandom(12)
    return iv + aes.encrypt(iv, dat, None)

def dec(key, pay):
    try:
        return AESGCM(key).decrypt(pay[:12], pay[12:], None)
    except:
        return None

def dot(kb):
    if not kb:
        return ""
    dig = hashlib.sha256(kb).digest()
    dts = [f"{dtc[dig[i] % len(dtc)]}●{crs}" for i in range(4)]
    return " ".join(dts)

class soc:
    def __init__(self, rdr, wtr, aky):
        self.r = rdr
        self.w = wtr
        self.aky = aky
        self.sek = None
        self.prv = x25519.X25519PrivateKey.generate()

    async def hsk(self):
        pub = self.prv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.w.write(pub)
        await self.w.drain()
        
        res = await self.r.readexactly(60)
        spb = x25519.X25519PublicKey.from_public_bytes(self.aky)
        sh1 = self.prv.exchange(spb)
        ky1 = kdf(None, sh1, b"NiosHandshake")
        
        seb = dec(ky1, res)
        if not seb:
            raise ConnectionError()
            
        sep = x25519.X25519PublicKey.from_public_bytes(seb)
        sh2 = self.prv.exchange(sep)
        self.sek = kdf(None, sh1 + sh2, b"NiosSocket")

    async def tx(self, dat):
        res = enc(self.sek, dat)
        self.w.write(len(res).to_bytes(4, 'big') + res)
        await self.w.drain()

    async def rx(self):
        lb = await self.r.readexactly(4)
        lng = int.from_bytes(lb, 'big')
        return dec(self.sek, await self.r.readexactly(lng))

nsk = None
sid = None
apr = None
lop = None
cht = {}
his = {}
cui = "main"
app = {"host": None, "port": None, "key": None, "active": False}

def clr():
    os.system('cls' if os.name == 'nt' else 'clear')

def lod():
    global app
    if os.path.exists(cfg):
        try:
            with open(cfg, "r") as f:
                app = json.load(f)
        except:
            pass

def sav():
    with open(cfg, "w") as f:
        json.dump(app, f)

def rcu():
    if not apr:
        return
        
    clr()
    dts = dot(cht[apr]["key"]) if apr in cht and cht[apr]["status"] == "secured" else ""
    
    print(f"{cbl}{cbd}=== CHAT: {apr} ==={crs}")
    if dts:
        print(f"       {dts}\n")
    print(f"{cye}Commands: /b (back) | /f <path> | /check_enc{crs}\n")
    
    for msg in his.get(apr, []):
        snd = msg["from"]
        if snd == sid:
            nm = "You"
            col = cgr
        elif snd == "System":
            nm = "System"
            col = cye
        else:
            nm = "Opponent"
            col = ccy
            
        if msg["is_file"]:
            print(f"{col}[{nm}]:{crs} {cye}[FILE: {msg['content']}]{crs}")
        else:
            print(f"{col}[{nm}]:{crs} {msg['content']}")
            
    print(f"\n{cbd}>{crs} ", end="")
    sys.stdout.flush()

def apm(pid, snd, con, isf=False):
    if pid not in his:
        his[pid] = []
    his[pid].append({"from": snd, "content": con, "is_file": isf})

async def lis():
    global nsk, sid, cht, his
    
    while True:
        if not app.get("active"):
            if nsk:
                try:
                    nsk.w.close()
                except:
                    pass
                nsk = None
            await asyncio.sleep(0.5)
            continue
            
        try:
            rdr, wtr = await asyncio.open_connection(app["host"], app["port"])
            aby = base64.b64decode(app["key"])
            sck = soc(rdr, wtr, aby)
            await sck.hsk()
            nsk = sck
            
            while app.get("active"):
                pkt = await nsk.rx()
                if not pkt:
                    break
                    
                pay = json.loads(pkt.decode())
                mtp = pay.get("type")
                
                if mtp == "system":
                    txt = pay.get("text", "")
                    if "ID" in txt:
                        sid = txt.split(":")[-1].strip()
                    continue
                    
                elif mtp == "message":
                    snd = pay.get("from")
                    txt = pay.get("text", "")
                    
                    if txt.startswith("HELO:"):
                        ppb = base64.b64decode(txt.split(":", 1)[1])
                        ppu = x25519.X25519PublicKey.from_public_bytes(ppb)
                        mpr = x25519.X25519PrivateKey.generate()
                        mpb = mpr.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                        mp6 = base64.b64encode(mpb).decode()
                        
                        shs = mpr.exchange(ppu)
                        sek = kdf(None, shs, b"NiosE2E")
                        
                        cht[snd] = {"status": "secured", "priv": mpr, "key": sek, "tx": 0, "rx": 0}
                        
                        rpk = json.dumps({"action": "send", "to": snd, "text": f"RESP:{mp6}"})
                        await nsk.tx(rpk.encode())
                        
                        dts = dot(sek)
                        smg = f"Chat established. Secure Key: {dts}"
                        apm(snd, "System", smg)
                        
                        if apr == snd and cui == "chat":
                            rcu()
                            sys.stdout.write(f"\r\033[K{cye}[System]: Chat secured. Key generated.{crs}\n> ")
                            sys.stdout.flush()
                        elif cui != "main":
                            sys.stdout.write(f"\r\033[K{cgr}[+] Secure Chat established with {snd}{crs}\n> ")
                            sys.stdout.flush()
                            
                    elif txt.startswith("RESP:"):
                        if snd in cht and cht[snd]["status"] == "connecting":
                            ppb = base64.b64decode(txt.split(":", 1)[1])
                            ppu = x25519.X25519PublicKey.from_public_bytes(ppb)
                            mpr = cht[snd]["priv"]
                            
                            shs = mpr.exchange(ppu)
                            sek = kdf(None, shs, b"NiosE2E")
                            
                            cht[snd]["key"] = sek
                            cht[snd]["status"] = "secured"
                            cht[snd]["tx"] = 0
                            cht[snd]["rx"] = 0
                            
                            dts = dot(sek)
                            smg = f"Chat secured. Secure Key: {dts}"
                            apm(snd, "System", smg)
                            
                            if apr == snd and cui == "chat":
                                rcu()
                                sys.stdout.write(f"\r\033[K{cye}[System]: Chat secured. Key generated.{crs}\n> ")
                                sys.stdout.flush()
                            elif cui != "main":
                                sys.stdout.write(f"\r\033[K{cgr}[+] Secure Chat established with {snd}{crs}\n> ")
                                sys.stdout.flush()
                                
                    elif txt.startswith("MSG:"):
                        pts = txt.split(":")
                        if len(pts) == 3 and snd in cht and cht[snd]["status"] == "secured":
                            cpl = base64.b64decode(pts[1]) + base64.b64decode(pts[2])
                            dcr = dec(cht[snd]["key"], cpl)
                            
                            if dcr:
                                mdt = json.loads(dcr.decode())
                                seq = mdt.get("s", 0)
                                if seq <= cht[snd].get("rx", 0):
                                    continue
                                cht[snd]["rx"] = seq
                                
                                ctp = mdt.get("t")
                                
                                if ctp == "cmd":
                                    ctx = mdt["c"]
                                    if ctx.startswith("CHK:"):
                                        phs = ctx[4:]
                                        mhs = base64.b64encode(hashlib.sha256(cht[snd]["key"]).digest()[:4]).decode()
                                        vrs = "OK" if phs == mhs else "ERR"
                                        sic(snd, vrs)
                                        
                                    elif ctx in ["OK", "ERR"]:
                                        alt = "[+] Auto-check OK! Compare dots manually." if ctx == "OK" else "[!] DANGER! Encryption mismatch! MITM possible!"
                                        alc = cgr if ctx == "OK" else cre
                                        if apr == snd and cui == "chat":
                                            sys.stdout.write(f"\r\033[K{alc}[System]: {alt}{crs}\n> ")
                                            sys.stdout.flush()
                                    continue
                                    
                                elif ctp == "file":
                                    b6d = mdt["d"].split(",")[1]
                                    fby = base64.b64decode(b6d)
                                    tpa = os.path.join(dld, mdt["n"])
                                    with open(tpa, "wb") as f:
                                        f.write(fby)
                                    cnt = f"{mdt['n']} (Saved to downloads)"
                                    isf = True
                                else:
                                    cnt = mdt["c"]
                                    isf = False
                                    
                                apm(snd, snd, cnt, isf)
                                
                                if apr == snd and cui == "chat":
                                    if isf:
                                        sys.stdout.write(f"\r\033[K{ccy}[Opponent]:{crs} {cye}[FILE: {cnt}]{crs}\n> ")
                                    else:
                                        sys.stdout.write(f"\r\033[K{ccy}[Opponent]:{crs} {cnt}\n> ")
                                    sys.stdout.flush()
                                else:
                                    sys.stdout.write(f"\r\033[K{cye}[!] New message from {snd}{crs}\n> ")
                                    sys.stdout.flush()
        except Exception:
            pass
            
        if app.get("active"):
            nsk = None
            sid = None
            if cui != "main":
                sys.stdout.write(f"\r\033[K{cre}[!] Connection lost. Reconnecting...{crs}\n> ")
                sys.stdout.flush()
            await asyncio.sleep(3)

def tun(pid):
    if pid in cht or not nsk:
        return
        
    eph = x25519.X25519PrivateKey.generate()
    cht[pid] = {"status": "connecting", "priv": eph, "key": None, "tx": 0, "rx": 0}
    
    pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pb6 = base64.b64encode(pub).decode()
    
    pay = json.dumps({"action": "send", "to": pid, "text": f"HELO:{pb6}"}).encode()
    asyncio.run_coroutine_threadsafe(nsk.tx(pay), lop)

def sic(pid, ctx):
    if pid not in cht or cht[pid]["status"] != "secured" or not nsk:
        return
        
    seq = cht[pid].get("tx", 0) + 1
    cht[pid]["tx"] = seq
    dat = json.dumps({"t": "cmd", "c": ctx, "s": seq}).encode()
    ebt = enc(cht[pid]["key"], dat)
    nce = base64.b64encode(ebt[:12]).decode()
    cph = base64.b64encode(ebt[12:]).decode()
    
    pay = json.dumps({"action": "send", "to": pid, "text": f"MSG:{nce}:{cph}"}).encode()
    asyncio.run_coroutine_threadsafe(nsk.tx(pay), lop)

def stm(pid, txt):
    if pid not in cht or cht[pid]["status"] != "secured" or not nsk:
        return
        
    seq = cht[pid].get("tx", 0) + 1
    cht[pid]["tx"] = seq
    dat = json.dumps({"t": "txt", "c": txt, "s": seq}).encode()
    ebt = enc(cht[pid]["key"], dat)
    nce = base64.b64encode(ebt[:12]).decode()
    cph = base64.b64encode(ebt[12:]).decode()
    
    apm(pid, sid, txt, False)
    
    pay = json.dumps({"action": "send", "to": pid, "text": f"MSG:{nce}:{cph}"}).encode()
    asyncio.run_coroutine_threadsafe(nsk.tx(pay), lop)

def sfa(pid, fpt):
    if pid not in cht or cht[pid]["status"] != "secured" or not nsk or not os.path.exists(fpt):
        return
        
    fnm = os.path.basename(fpt)
    with open(fpt, "rb") as f:
        fb6 = base64.b64encode(f.read()).decode()
        
    seq = cht[pid].get("tx", 0) + 1
    cht[pid]["tx"] = seq
    dat = json.dumps({"t": "file", "n": fnm, "d": f"b64,{fb6}", "s": seq}).encode()
    ebt = enc(cht[pid]["key"], dat)
    nce = base64.b64encode(ebt[:12]).decode()
    cph = base64.b64encode(ebt[12:]).decode()
    
    apm(pid, sid, fnm, True)
    
    pay = json.dumps({"action": "send", "to": pid, "text": f"MSG:{nce}:{cph}"}).encode()
    asyncio.run_coroutine_threadsafe(nsk.tx(pay), lop)

def own():
    clr()
    print(f"{cbl}=== CREATE OWN NODE ==={crs}\n")
    
    wsr = f"""@echo off
echo [*] Opening Firewall...
netsh advfirewall firewall add rule name="Nios Node" dir=in action=allow protocol=TCP localport=7234
echo [*] Installing Dependencies...
pip install cryptography
echo [*] Generating Server Script...
python -c "import base64; open('server.py', 'wb').write(base64.b64decode('{b64}'))"
echo [*] Launching Node...
python server.py
pause"""

    lsr = f"""#!/bin/bash
echo "[*] Opening Firewall..."
sudo ufw allow 7234/tcp || sudo iptables -A INPUT -p tcp --dport 7234 -j ACCEPT
echo "[*] Installing Dependencies..."
sudo apt-get update && sudo apt-get install -y python3-pip
pip3 install cryptography --break-system-packages 2>/dev/null || pip3 install cryptography
echo "[*] Generating Server Script..."
python3 -c "import base64; open('server.py', 'wb').write(base64.b64decode('{b64}'))"
echo "[*] Launching Node..."
python3 server.py"""

    try:
        with open(os.path.join(bdr, "deploy_win.bat"), "w") as f:
            f.write(wsr)
        with open(os.path.join(bdr, "deploy_lin.sh"), "w") as f:
            f.write(lsr)
            
        if os.name != 'nt':
            os.chmod(os.path.join(bdr, "deploy_lin.sh"), 0o755)
            
        print(f"{cgr}[+] Export successful. Scripts saved to your PC.{crs}")
        print(f" -> deploy_win.bat (Windows)")
        print(f" -> deploy_lin.sh  (Linux)")
    except Exception as e:
        print(f"{cre}[!] Export failed: {e}{crs}")
        
    input("\nPress Enter to return...")

def hci():
    global apr
    msg = input().strip()
    
    if msg in ["/b", "/back"]:
        apr = None
        return
        
    if not msg:
        sys.stdout.write(f"\033[1A\033[K> ")
        sys.stdout.flush()
        return
        
    sts = cht[apr]["status"]
    if sts != "secured":
        sys.stdout.write(f"\033[1A\033[K{cre}[System]: Connection not secured yet. Please wait.{crs}\n> ")
        sys.stdout.flush()
        return
        
    if msg == "/check_enc":
        sys.stdout.write(f"\033[1A\033[K{cye}[System]:{crs} [*] Initiating auto-check...\n> ")
        sys.stdout.flush()
        mhs = base64.b64encode(hashlib.sha256(cht[apr]["key"]).digest()[:4]).decode()
        sic(apr, f"CHK:{mhs}")
        
    elif msg.startswith("/f ") or msg.startswith("/file "):
        fpt = msg.split(" ", 1)[1].strip()
        if os.path.exists(fpt):
            fnm = os.path.basename(fpt)
            sys.stdout.write(f"\033[1A\033[K{cgr}[You]:{crs} {cye}[FILE: {fnm}]{crs}\n> ")
            sys.stdout.flush()
            sfa(apr, fpt)
        else:
            sys.stdout.write(f"\033[1A\033[K{cre}[System]: File not found.{crs}\n> ")
            sys.stdout.flush()
            
    else:
        sys.stdout.write(f"\033[1A\033[K{cgr}[You]:{crs} {msg}\n> ")
        sys.stdout.flush()
        stm(apr, msg)

def eml():
    global apr, sid, cui
    lod()
    
    while True:
        cui = "main"
        clr()
        print(f"{cbl}{cbd}--- e2e manager ---{crs}")
        print(f"Downloads: {dld}\n")
        print("1. Connect to Node")
        print("2. Create own node")
        print("3. Exit")
        
        if app.get("active"):
            print(f"\n{cgr}[*] You can connect at ur saved node: {app['host']}:{app['port']}{crs}")
            
        chc = input("\n> ").strip()
        
        if chc == "1":
            clr()
            if app.get("host"):
                print(f"Saved Node: {app['host']}:{app['port']}")
                if input("Use saved node? (y/n): ").strip().lower() != 'y':
                    app["host"] = input("Host: ").strip()
                    pts = input("Port [7234]: ").strip()
                    app["port"] = int(pts) if pts else 7234
                    app["key"] = input("Access Key: ").strip()
            else:
                app["host"] = input("Host: ").strip()
                pts = input("Port [7234]: ").strip()
                app["port"] = int(pts) if pts else 7234
                app["key"] = input("Access Key: ").strip()
                
            app["active"] = True
            sav()
            
            print(f"{cye}Establishing secure socket...{crs}")
            tm = 10.0
            while tm > 0 and not sid and app["active"]:
                time.sleep(0.5)
                tm -= 0.5
                
            if not sid:
                print(f"{cre}Connection failed.{crs}")
                app["active"] = False
                time.sleep(2.0)
                continue
                
            while app["active"]:
                if apr:
                    cui = "chat"
                    time.sleep(0.5)
                    continue
                    
                cui = "session"
                clr()
                print(f"{cbl}--- Menu ---{crs}")
                print(f"Your ID: {cgr}{sid}{crs}\n")
                print("1. New Chat (Connect to Peer)")
                print("2. Active Chats")
                print("3. Check Encryption")
                print("4. Disconnect Node")
                
                cmd = input("\n> ").strip()
                
                if cmd == "1":
                    per = input("Enter PeerID: ").strip().upper()
                    if len(per) == 6:
                        tun(per)
                        apr = per
                        cui = "chat"
                        rcu()
                        while apr and app["active"]:
                            hci()
                                
                elif cmd == "2":
                    while True:
                        cui = "session"
                        clr()
                        print(f"{cbl}--- Chats ---{crs}")
                        cks = list(cht.keys())
                        
                        if not cks:
                            print("No active chats.")
                            
                        for i, pid in enumerate(cks):
                            sts = "Secured" if cht[pid]["status"] == "secured" else "Connecting"
                            print(f"{i}. {pid} [{sts}]")
                            
                        sel = input("\nEnter number to open chat, or 'b' to go back: ").strip()
                        if sel.lower() == 'b':
                            break
                            
                        if sel.isdigit() and int(sel) < len(cks):
                            apr = cks[int(sel)]
                            cui = "chat"
                            rcu()
                            while apr and app["active"]:
                                hci()
                                    
                elif cmd == "3":
                    while True:
                        clr()
                        print(f"{cbl}--- Verify Encryption ---{crs}")
                        sch = [k for k, v in cht.items() if v["status"] == "secured"]
                        
                        if not sch:
                            print("No secured chats available.")
                            input("\nPress Enter to return...")
                            break
                            
                        for i, pid in enumerate(sch):
                            print(f"{i}. {pid}")
                            
                        sel = input("\nSelect chat to verify, or 'b' to go back: ").strip()
                        if sel.lower() == 'b':
                            break
                            
                        if sel.isdigit() and int(sel) < len(sch):
                            per = sch[int(sel)]
                            clr()
                            print(f"{cbl}--- Verify Encryption: {per} ---{crs}\n")
                            print(f"       {dot(cht[per]['key'])}\n")
                            print("Both peers must see the exact same colors in the exact same order.")
                            print("If colors differ, your connection is compromised (MITM).\n")
                            input("Press Enter to return...")
                            
                elif cmd == "4":
                    app["active"] = False
                    sid = None
                    cht.clear()
                    his.clear()
                    
        elif chc == "2":
            own()
        elif chc == "3":
            sys.exit(0)

def sat(lop):
    asyncio.set_event_loop(lop)
    lop.create_task(lis())
    lop.run_forever()

if __name__ == "__main__":
    lop = asyncio.new_event_loop()
    threading.Thread(target=sat, args=(lop,), daemon=True).start()
    eml()
    
#guys sorry for shit in my code-style, im fine for this :)
