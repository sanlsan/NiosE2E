import os
import sys
import json
import time
import base64
import asyncio
import threading
import hashlib
import re
import secrets
import gc
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if os.name == 'nt':
    os.system("")

basedir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
down_dr = os.path.join(basedir, "downloads")
os.makedirs(down_dr, exist_ok=True)
cfgpath = os.path.join(basedir, "config.json")

clrblue = "\033[94m"
clrgren = "\033[92m"
clr_red = "\033[91m"
clryllw = "\033[93m"
clrcyan = "\033[96m"
clrmgnt = "\033[95m"
clrwhte = "\033[97m"
clrbold = "\033[1m"
clr_rst = "\033[0m"

color_l = [clr_red, clrgren, clryllw, clrblue, clrmgnt, clrcyan, clrwhte]

srvsrcs = """import asyncio, os, base64, json, secrets
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hkdf_dr(salt_by, mat_byt, inf_byt):
    return HKDF(SHA256(), 32, salt_by, inf_byt).derive(mat_byt)

def enc_aed(enc_key, dat_byt, add_dat=None):
    aes_gcm = AESGCM(enc_key)
    init_vc = os.urandom(12)
    return init_vc + aes_gcm.encrypt(init_vc, dat_byt, add_dat)

def dec_aed(enc_key, cip_pay, add_dat=None):
    try:
        return AESGCM(enc_key).decrypt(cip_pay[:12], cip_pay[12:], add_dat)
    except:
        return None

class SrvSess:
    def __init__(self, read_io, writ_io, stat_ky):
        self.read_io = read_io
        self.writ_io = writ_io
        self.stat_ky = stat_ky
        self.sess_ky = None
        self.ephe_ky = x25519.X25519PrivateKey.generate()

    async def handshake(self):
        clipubb = await self.read_io.readexactly(32)
        clipubk = x25519.X25519PublicKey.from_public_bytes(clipubb)
        sh_sec1 = self.stat_ky.exchange(clipubk)
        hand_ky = hkdf_dr(None, sh_sec1, b"NiosHandshake")
        sh_sec2 = self.ephe_ky.exchange(clipubk)
        self.sess_ky = hkdf_dr(None, sh_sec1 + sh_sec2, b"NiosSocket")
        ep_pubb = self.ephe_ky.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.writ_io.write(enc_aed(hand_ky, ep_pubb))
        await self.writ_io.drain()

    async def send_packet(self, payload):
        enc_pay = enc_aed(self.sess_ky, payload)
        self.writ_io.write(len(enc_pay).to_bytes(4, 'big') + enc_pay)
        await self.writ_io.drain()

    async def receive_packet(self):
        len_byt = await self.read_io.readexactly(4)
        pay_len = int.from_bytes(len_byt, 'big')
        enc_pay = await self.read_io.readexactly(pay_len)
        dec_pay = dec_aed(self.sess_ky, enc_pay)
        if not dec_pay:
            raise ConnectionError("Server session AEAD validation failed.")
        return dec_pay

clients = {}
usrpath = "users.json"

def loadusr():
    if os.path.exists(usrpath):
        with open(usrpath, "r") as fil_obj:
            return json.load(fil_obj)
    return {}

def saveusr(usr_dbx):
    with open(usrpath, "w") as fil_obj:
        json.dump(usr_dbx, fil_obj)

async def hnd_con(read_io, writ_io, stat_ky):
    session = SrvSess(read_io, writ_io, stat_ky)
    try:
        await session.handshake()
    except:
        return writ_io.close()
    
    try:
        authreq = await session.receive_packet()
        authdat = json.loads(authreq.decode())
        if authdat.get("action") != "auth": raise Exception()
        peer_id = authdat["peer_id"]
        pub_b64 = authdat["pub"]
        
        usr_dbx = loadusr()
        if peer_id not in usr_dbx:
            usr_dbx[peer_id] = pub_b64
            saveusr(usr_dbx)
        elif usr_dbx[peer_id] != pub_b64:
            raise Exception()
            
        challen = os.urandom(32).hex()
        await session.send_packet(json.dumps({"type": "challenge", "data": challen}).encode())
        
        respreq = await session.receive_packet()
        respdat = json.loads(respreq.decode())
        if respdat.get("action") != "auth_resp": raise Exception()
        
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub_key.verify(bytes.fromhex(respdat["sig"]), bytes.fromhex(challen))
        
        sess_id = peer_id
        clients[sess_id] = session
        print(f"[+] Client connected: {sess_id}")
        
        await session.send_packet(json.dumps({"type": "system", "text": f"Session ID:{sess_id}"}).encode())
        while True:
            rec_dat = await session.receive_packet()
            dat_jsn = json.loads(rec_dat.decode())
            if dat_jsn.get("action") == "send":
                tgt_pee = dat_jsn.get("to")
                msg_txt = dat_jsn.get("text")
                if tgt_pee in clients:
                    await clients[tgt_pee].send_packet(json.dumps({"type": "message", "from": sess_id, "text": msg_txt}).encode())
    except Exception as err_exc:
        pass
    finally:
        if 'sess_id' in locals() and sess_id in clients:
            clients.pop(sess_id, None)
            print(f"[-] Client disconnected: {sess_id}")
        writ_io.close()

async def run_srv():
    keyfile = "server.key"
    if os.path.exists(keyfile):
        with open(keyfile, "rb") as fil_obj:
            stat_ky = x25519.X25519PrivateKey.from_private_bytes(fil_obj.read())
    else:
        stat_ky = x25519.X25519PrivateKey.generate()
        with open(keyfile, "wb") as fil_obj:
            fil_obj.write(stat_ky.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
            
    pubbyts = stat_ky.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pubbyts).decode()
    srv_obj = await asyncio.start_server(lambda r, w: hnd_con(r, w, stat_ky), '0.0.0.0', 7234)
    print(f"PORT: 7234\\\\nACCESS KEY: {pub_b64}\\\\n")
    async with srv_obj:
        await srv_obj.serve_forever()

if __name__ == '__main__':
    asyncio.run(run_srv())"""

srv_b64 = base64.b64encode(srvsrcs.encode()).decode()

def hkdf_dr(salt_by, mat_byt, inf_byt):
    return HKDF(SHA256(), 32, salt_by, inf_byt).derive(mat_byt)

def kdfrk_f(rat_key, dh_outs):
    hkdf_ob = HKDF(SHA256(), 64, rat_key, b"KDF_RK")
    out_val = hkdf_ob.derive(dh_outs)
    return out_val[:32], out_val[32:]

def kdfck_f(chn_key):
    hkdf_ob = HKDF(SHA256(), 64, None, b"KDF_CK")
    out_val = hkdf_ob.derive(chn_key)
    return out_val[:32], out_val[32:]

def enc_aed(enc_key, dat_byt, add_dat=None):
    aes_gcm = AESGCM(enc_key)
    init_vc = os.urandom(12)
    return init_vc + aes_gcm.encrypt(init_vc, dat_byt, add_dat)

def dec_aed(enc_key, cip_pay, add_dat=None):
    try:
        return AESGCM(enc_key).decrypt(cip_pay[:12], cip_pay[12:], add_dat)
    except:
        return None

def get_wrd(key_byt):
    if not key_byt:
        return ""
    dig_byt = hashlib.sha256(key_byt).digest()
    wrd_lst = [
        "acid", "apex", "band", "bark", "beta", "bolt", "born", "calm", "clay", "coal",
        "dark", "dawn", "echo", "edge", "envy", "fade", "film", "flow", "flux", "glow",
        "grid", "hawk", "haze", "hint", "icon", "iron", "jade", "jolt", "kept", "lava",
        "leaf", "limo", "maze", "mist", "neon", "node", "opal", "open", "path", "pave",
        "rift", "rust", "sand", "silk", "spark", "tide", "toad", "volt", "wave", "zinc"
    ]
    elem_ls = []
    for idx_val in range(4):
        wrd_idx = dig_byt[idx_val * 2] % 50
        clr_idx = dig_byt[idx_val * 2 + 1] % len(color_l)
        word_st = wrd_lst[wrd_idx]
        colr_vl = color_l[clr_idx]
        elem_ls.append(f"{colr_vl}{word_st}{clr_rst}")
    return " | ".join(elem_ls)

def skip_ks(session, unt_val):
    if session["num_rcv"] + 100 < unt_val:
        raise ConnectionError("Too many skipped messages")
    if session["chn_krx"] is not None:
        while session["num_rcv"] < unt_val:
            session["chn_krx"], msg_key = kdfck_f(session["chn_krx"])
            session["skip_ks"][f"{session['dhr_key']}_{session['num_rcv']}"] = msg_key
            session["num_rcv"] += 1

def dhratch(session, headers):
    session["prv_num"] = session["num_snt"]
    session["num_snt"] = 0
    session["num_rcv"] = 0
    session["dhr_key"] = headers["dh"]
    dhrbyts = base64.b64decode(session["dhr_key"])
    dhr_key = x25519.X25519PublicKey.from_public_bytes(dhrbyts)
    session["rat_key"], session["chn_krx"] = kdfrk_f(session["rat_key"], session["dhs_key"].exchange(dhr_key))
    session["dhs_key"] = x25519.X25519PrivateKey.generate()
    session["rat_key"], session["chn_ksx"] = kdfrk_f(session["rat_key"], session["dhs_key"].exchange(dhr_key))

def encrypt(session, typ_val, content):
    session["chn_ksx"], msg_key = kdfck_f(session["chn_ksx"])
    dh_publ = session["dhs_key"].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    headers = {
        "dh": base64.b64encode(dh_publ).decode(),
        "pn": session["prv_num"],
        "n": session["num_snt"]
    }
    session["num_snt"] += 1
    metadat = {"t": typ_val}
    if typ_val == "file":
        metadat["n"] = content[0]
        metadat["d"] = content[1]
    else:
        metadat["c"] = content
    pad_len = secrets.randbelow(113) + 16
    metadat["p"] = secrets.token_hex(pad_len // 2)
    
    hdr_b64 = base64.b64encode(json.dumps(headers).encode()).decode()
    hdr_byt = base64.b64decode(hdr_b64)
    enc_dat = enc_aed(msg_key, json.dumps(metadat).encode(), hdr_byt)
    
    session["key_val"] = hkdf_dr(None, msg_key, b"Visual")
    gc.collect()
    return hdr_b64, enc_dat

def decrypt(session, hdr_b64, ciph_dt):
    hdr_byt = base64.b64decode(hdr_b64)
    headers = json.loads(hdr_byt.decode())
    
    mks_key = f"{headers['dh']}_{headers['n']}"
    if mks_key in session["skip_ks"]:
        msg_key = session["skip_ks"].pop(mks_key)
        pla_txt = dec_aed(msg_key, ciph_dt, hdr_byt)
        session["prv_key"] = session["key_val"]
        session["key_val"] = hkdf_dr(None, msg_key, b"Visual")
        gc.collect()
        return pla_txt

    tmp_ses = {
        "rat_key": session["rat_key"],
        "chn_ksx": session["chn_ksx"],
        "chn_krx": session["chn_krx"],
        "num_snt": session["num_snt"],
        "num_rcv": session["num_rcv"],
        "prv_num": session["prv_num"],
        "dhr_key": session["dhr_key"],
        "dhs_key": session["dhs_key"],
        "skip_ks": session["skip_ks"].copy(),
        "key_val": session["key_val"]
    }

    try:
        if headers["dh"] != tmp_ses["dhr_key"]:
            skip_ks(tmp_ses, headers["pn"])
            dhratch(tmp_ses, headers)
        
        skip_ks(tmp_ses, headers["n"])
        tmp_ses["chn_krx"], msg_key = kdfck_f(tmp_ses["chn_krx"])
        tmp_ses["num_rcv"] += 1
        
        pla_txt = dec_aed(msg_key, ciph_dt, hdr_byt)
        if pla_txt is not None:
            for key_var in tmp_ses:
                session[key_var] = tmp_ses[key_var]
            session["prv_key"] = session["key_val"]
            session["key_val"] = hkdf_dr(None, msg_key, b"Visual")
            gc.collect()
            return pla_txt
        return None
    except Exception:
        return None

class CliSock:
    def __init__(self, read_io, writ_io, acc_key):
        self.read_io = read_io
        self.writ_io = writ_io
        self.acc_key = acc_key
        self.sess_ky = None
        self.priv_ky = x25519.X25519PrivateKey.generate()

    async def handshake(self):
        pubbyts = self.priv_ky.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.writ_io.write(pubbyts)
        await self.writ_io.drain()
        
        resp_io = await self.read_io.readexactly(60)
        srv_pub = x25519.X25519PublicKey.from_public_bytes(self.acc_key)
        sh_key1 = self.priv_ky.exchange(srv_pub)
        hand_ky = hkdf_dr(None, sh_key1, b"NiosHandshake")
        
        dec_byt = dec_aed(hand_ky, resp_io)
        if not dec_byt:
            raise ConnectionError("Handshake AEAD decryption failed.")
            
        eph_pub = x25519.X25519PublicKey.from_public_bytes(dec_byt)
        sh_key2 = self.priv_ky.exchange(eph_pub)
        self.sess_ky = hkdf_dr(None, sh_key1 + sh_key2, b"NiosSocket")
        gc.collect()

    async def send_packet(self, payload):
        enc_pay = enc_aed(self.sess_ky, payload)
        self.writ_io.write(len(enc_pay).to_bytes(4, 'big') + enc_pay)
        await self.writ_io.drain()

    async def receive_packet(self):
        len_byt = await self.read_io.readexactly(4)
        pay_len = int.from_bytes(len_byt, 'big')
        enc_pay = await self.read_io.readexactly(pay_len)
        dec_pay = dec_aed(self.sess_ky, enc_pay)
        if not dec_pay:
            raise ConnectionError("Socket AEAD validation failed.")
        return dec_pay

nod_sck = None
sess_id = None
actpeer = None
evt_lop = None
chats_s = {}
msghist = {}
curr_ui = "main"
app_cfg = {"host": None, "port": None, "key": None, "active": False, "anon_mode": False}

my_ed_priv = None
my_ed_pub = None
verified_peers = {}

def encrypt_verified_data(data_dict):
    if not my_ed_priv:
        return ""
    try:
        priv_bytes = my_ed_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        cfg_key = hashlib.sha256(priv_bytes).digest()
        serialized = json.dumps(data_dict).encode()
        aes_gcm = AESGCM(cfg_key)
        nonce = os.urandom(12)
        ct = aes_gcm.encrypt(nonce, serialized, None)
        return base64.b64encode(nonce + ct).decode()
    except:
        return ""

def decrypt_verified_data(encrypted_str):
    if not my_ed_priv or not encrypted_str:
        return {}
    try:
        priv_bytes = my_ed_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        cfg_key = hashlib.sha256(priv_bytes).digest()
        enc_data = base64.b64decode(encrypted_str)
        nonce = enc_data[:12]
        ct = enc_data[12:]
        aes_gcm = AESGCM(cfg_key)
        decrypted = aes_gcm.decrypt(nonce, ct, None)
        return json.loads(decrypted.decode())
    except:
        return {}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def loadcfg():
    global app_cfg
    if os.path.exists(cfgpath):
        try:
            with open(cfgpath, "r") as cfgfile:
                app_cfg.update(json.load(cfgfile))
        except:
            pass

def savecfg():
    with open(cfgpath, "w") as cfgfile:
        json.dump({key_var: val_var for key_var, val_var in app_cfg.items() if key_var not in ["active", "anon_mode", "anon_prv"]}, cfgfile)

def getauth(hst_val, prt_val, is_anon):
    if is_anon:
        if "anon_prv" not in app_cfg:
            prv_key = ed25519.Ed25519PrivateKey.generate()
            prvbyts = prv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            app_cfg["anon_prv"] = base64.b64encode(prvbyts).decode()
        prvbyts = base64.b64decode(app_cfg["anon_prv"])
        prv_key = ed25519.Ed25519PrivateKey.from_private_bytes(prvbyts)
        pubbyts = prv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        peer_id = hashlib.sha256(pubbyts).digest()[:8].hex().upper()
        return prv_key, base64.b64encode(pubbyts).decode(), peer_id

    nod_key = f"{hst_val}:{prt_val}"
    if "nodes" not in app_cfg:
        app_cfg["nodes"] = {}
    if nod_key not in app_cfg["nodes"]:
        prv_key = ed25519.Ed25519PrivateKey.generate()
        prvbyts = prv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        app_cfg["nodes"][nod_key] = base64.b64encode(prvbyts).decode()
        savecfg()
    
    prvbyts = base64.b64decode(app_cfg["nodes"][nod_key])
    prv_key = ed25519.Ed25519PrivateKey.from_private_bytes(prvbyts)
    pubbyts = prv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    peer_id = hashlib.sha256(pubbyts).digest()[:8].hex().upper()
    return prv_key, base64.b64encode(pubbyts).decode(), peer_id

def disc_nd():
    global nod_sck, sess_id, my_ed_priv, my_ed_pub, verified_peers
    is_anon = app_cfg.get("anon_mode", False)
    app_cfg["active"] = False
    if nod_sck:
        try:
            nod_sck.writ_io.close()
        except:
            pass
        nod_sck = None
    sess_id = None
    chats_s.clear()
    msghist.clear()
    my_ed_priv = None
    my_ed_pub = None
    verified_peers.clear()
    if "anon_prv" in app_cfg:
        del app_cfg["anon_prv"]
    if is_anon:
        app_cfg["host"] = None
        app_cfg["port"] = None
        app_cfg["key"] = None
        app_cfg["anon_mode"] = False
    gc.collect()

def show_ui():
    if not actpeer:
        return
        
    clear_screen()
    wrd_str = get_wrd(chats_s[actpeer]["key_val"]) if actpeer in chats_s and chats_s[actpeer]["stat_us"] == "secured" else ""
    
    is_verified = actpeer in verified_peers
    status_str = f"{clrgren}[Verified]{clr_rst}" if is_verified else f"{clryllw}[Unverified]{clr_rst}"
    
    print(f"{clrblue}{clrbold}--- CHAT: {status_str} {actpeer} ---{clr_rst}")
    if wrd_str:
        print(f" Key: {wrd_str}\n")
    print(f"{clryllw}Commands: /b (back) | /f <path> | /verify | /check_enc{clr_rst}\n")
    
    if actpeer in chats_s and chats_s[actpeer]["stat_us"] == "compromised":
        print(f"{clr_red}{clrbold}Peer's security key has changed! Active Man-in-the-Middle attack suspected. Transmission blocked. Re-verify the visual words!{clr_rst}\n")
    
    for msg_obj in msghist.get(actpeer, []):
        snd_val = msg_obj["from"]
        if snd_val == sess_id:
            nam_tag = "You"
            nam_clr = clrgren
        elif snd_val == "System":
            nam_tag = "System"
            nam_clr = clryllw
        else:
            nam_tag = "Opponent"
            nam_clr = clrcyan
            
        if msg_obj["is_file"]:
            print(f"{nam_clr}[{nam_tag}]:{clr_rst} {clryllw}[FILE: {msg_obj['content']}]{clr_rst}")
        else:
            print(f"{nam_clr}[{nam_tag}]:{clr_rst} {msg_obj['content']}")
            
    print(f"\n{clrbold}>{clr_rst} ", end="")
    sys.stdout.flush()

def addhist(peer_id, send_id, content, is_file=False):
    if peer_id not in msghist:
        msghist[peer_id] = []
    msghist[peer_id].append({"from": send_id, "content": content, "is_file": is_file})

async def socklop():
    global nod_sck, sess_id, chats_s, msghist, my_ed_priv, my_ed_pub, verified_peers
    
    while True:
        if not app_cfg.get("active"):
            if nod_sck:
                try: nod_sck.writ_io.close()
                except: pass
                nod_sck = None
            await asyncio.sleep(0.5)
            continue
            
        try:
            read_io, writ_io = await asyncio.open_connection(app_cfg["host"], app_cfg["port"])
            dec_key = base64.b64decode(app_cfg["key"])
            sck_ses = CliSock(read_io, writ_io, dec_key)
            await sck_ses.handshake()
            nod_sck = sck_ses
            
            ed_priv, ed_publ, peer_id = getauth(app_cfg["host"], app_cfg["port"], app_cfg.get("anon_mode", False))
            my_ed_priv = ed_priv
            my_ed_pub = base64.b64decode(ed_publ)
            
            enc_data = app_cfg.get("verified_encrypted", "")
            verified_peers = decrypt_verified_data(enc_data)
            
            await nod_sck.send_packet(json.dumps({"action": "auth", "peer_id": peer_id, "pub": ed_publ}).encode())
            
            chl_pkt = await nod_sck.receive_packet()
            chl_dat = json.loads(chl_pkt.decode())
            if chl_dat.get("type") != "challenge": raise Exception()
            
            sig_val = ed_priv.sign(bytes.fromhex(chl_dat["data"]))
            await nod_sck.send_packet(json.dumps({"action": "auth_resp", "sig": sig_val.hex()}).encode())
            
            sys_pkt = await nod_sck.receive_packet()
            sys_dat = json.loads(sys_pkt.decode())
            if "ID" in sys_dat.get("text", ""):
                sess_id = sys_dat["text"].split(":")[-1].strip()
            
            while app_cfg.get("active"):
                pkt_byt = await nod_sck.receive_packet()
                if not pkt_byt:
                    break
                    
                pay_jsn = json.loads(pkt_byt.decode())
                msg_typ = pay_jsn.get("type")
                
                if msg_typ == "system":
                    continue
                    
                elif msg_typ == "message":
                    send_id = pay_jsn.get("from")
                    msg_txt = pay_jsn.get("text", "")
                    
                    if msg_txt.startswith("HELO:"):
                        parts_l = msg_txt.split(":")
                        if len(parts_l) >= 4:
                            pubbyts = base64.b64decode(parts_l[1])
                            pub_ed_byts = base64.b64decode(parts_l[2])
                            sig_byts = base64.b64decode(parts_l[3])
                            
                            expected_peer_id = hashlib.sha256(pub_ed_byts).digest()[:8].hex().upper()
                            if expected_peer_id != send_id:
                                continue
                                
                            try:
                                peer_ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_ed_byts)
                                peer_ed_pub.verify(sig_byts, pubbyts)
                            except:
                                continue
                                
                            pub_ed_b64 = base64.b64encode(pub_ed_byts).decode()
                            if send_id in verified_peers:
                                if verified_peers[send_id] != pub_ed_b64:
                                    sys.stdout.write(f"\r\033[K\n{clr_red}{clrbold}[!!!] WARNING: Your peer's security key has changed! Active MITM attack suspected. Transmission blocked. Re-verify visual words!{clr_rst}\n> ")
                                    sys.stdout.flush()
                                    chats_s[send_id] = {
                                        "stat_us": "compromised",
                                        "key_val": None
                                    }
                                    if actpeer == send_id and curr_ui == "chat":
                                        show_ui()
                                    continue
                            
                            pub_key = x25519.X25519PublicKey.from_public_bytes(pubbyts)
                            prv_key = x25519.X25519PrivateKey.generate()
                            resp_pubbyts = prv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                            resp_pub_b64 = base64.b64encode(resp_pubbyts).decode()
                            
                            res_sig = my_ed_priv.sign(resp_pubbyts)
                            resp_ed_b64 = base64.b64encode(my_ed_pub).decode()
                            resp_sig_b64 = base64.b64encode(res_sig).decode()
                            
                            sh_key1 = prv_key.exchange(pub_key)
                            rat_key = sh_key1
                            rat_key, chn_krx = kdfrk_f(rat_key, sh_key1)
                            dhs_key = x25519.X25519PrivateKey.generate()
                            dhr_key = base64.b64encode(pubbyts).decode()
                            rat_key, chn_ksx = kdfrk_f(rat_key, dhs_key.exchange(pub_key))
                            
                            chats_s[send_id] = {
                                "stat_us": "secured",
                                "dhs_key": dhs_key,
                                "dhr_key": dhr_key,
                                "rat_key": rat_key,
                                "chn_ksx": chn_ksx,
                                "chn_krx": chn_krx,
                                "num_snt": 0,
                                "num_rcv": 0,
                                "prv_num": 0,
                                "skip_ks": {},
                                "key_val": hkdf_dr(None, sh_key1, b"Visual"),
                                "prv_key": None,
                                "peer_static_ed": pub_ed_b64
                            }
                            
                            res_pay = json.dumps({"action": "send", "to": send_id, "text": f"RESP:{resp_pub_b64}:{resp_ed_b64}:{resp_sig_b64}"})
                            await nod_sck.send_packet(res_pay.encode())
                            
                            if actpeer == send_id and curr_ui == "chat":
                                show_ui()
                            elif curr_ui != "main":
                                sys.stdout.write(f"\r\033[K{clrgren}[+] Secure Chat established with {send_id}{clr_rst}\n> ")
                                sys.stdout.flush()
                            
                    elif msg_txt.startswith("RESP:"):
                        if send_id in chats_s and chats_s[send_id]["stat_us"] == "connecting":
                            parts_l = msg_txt.split(":")
                            if len(parts_l) >= 4:
                                pubbyts = base64.b64decode(parts_l[1])
                                pub_ed_byts = base64.b64decode(parts_l[2])
                                sig_byts = base64.b64decode(parts_l[3])
                                
                                expected_peer_id = hashlib.sha256(pub_ed_byts).digest()[:8].hex().upper()
                                if expected_peer_id != send_id:
                                    continue
                                    
                                try:
                                    peer_ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_ed_byts)
                                    peer_ed_pub.verify(sig_byts, pubbyts)
                                except:
                                    continue
                                    
                                pub_ed_b64 = base64.b64encode(pub_ed_byts).decode()
                                if send_id in verified_peers:
                                    if verified_peers[send_id] != pub_ed_b64:
                                        sys.stdout.write(f"\r\033[K\n{clr_red}{clrbold}[!!!] WARNING: Your peer's security key has changed! Active MITM attack suspected. Transmission blocked. Re-verify visual words!{clr_rst}\n> ")
                                        sys.stdout.flush()
                                        chats_s[send_id] = {
                                            "stat_us": "compromised",
                                            "key_val": None
                                        }
                                        if actpeer == send_id and curr_ui == "chat":
                                            show_ui()
                                        continue
                                
                                pub_key = x25519.X25519PublicKey.from_public_bytes(pubbyts)
                                prv_key = chats_s[send_id]["prv_key"]
                                
                                sh_key1 = prv_key.exchange(pub_key)
                                rat_key = sh_key1
                                dhs_key = prv_key
                                dhr_key = base64.b64encode(pubbyts).decode()
                                rat_key, chn_ksx = kdfrk_f(rat_key, sh_key1)
                                chn_krx = None
                                
                                chats_s[send_id] = {
                                    "stat_us": "secured",
                                    "dhs_key": dhs_key,
                                    "dhr_key": dhr_key,
                                    "rat_key": rat_key,
                                    "chn_ksx": chn_ksx,
                                    "chn_krx": chn_krx,
                                    "num_snt": 0,
                                    "num_rcv": 0,
                                    "prv_num": 0,
                                    "skip_ks": {},
                                    "key_val": hkdf_dr(None, sh_key1, b"Visual"),
                                    "prv_key": None,
                                    "peer_static_ed": pub_ed_b64
                                }
                                
                                if actpeer == send_id and curr_ui == "chat":
                                    show_ui()
                                elif curr_ui != "main":
                                    sys.stdout.write(f"\r\033[K{clrgren}[+] Secure Chat established with {send_id}{clr_rst}\n> ")
                                    sys.stdout.flush()
                                
                    elif msg_txt.startswith("MSG:"):
                        parts_l = msg_txt.split(":")
                        if len(parts_l) == 3 and send_id in chats_s:
                            if chats_s[send_id]["stat_us"] == "compromised":
                                continue
                            
                            if chats_s[send_id]["stat_us"] == "secured":
                                hdr_b64 = parts_l[1]
                                cip_pay = base64.b64decode(parts_l[2])
                                
                                dec_msg = decrypt(chats_s[send_id], hdr_b64, cip_pay)
                                
                                if not dec_msg:
                                    sys.stdout.write(f"\r\033[K{clr_red}[!] S-Alert: E2E message decryption failed! Tampering or MITM attack detected! Instantly disconnecting...{clr_rst}\n> ")
                                    sys.stdout.flush()
                                    disc_nd()
                                    break
                                
                                metadat = json.loads(dec_msg.decode())
                                con_typ = metadat.get("t")
                                
                                if con_typ == "cmd":
                                    cmd_ctx = metadat["c"]
                                    if cmd_ctx.startswith("CHK:"):
                                        p_hashx = cmd_ctx[4:]
                                        chk_key = chats_s[send_id]["key_val"]
                                        m_hashx = base64.b64encode(hashlib.sha256(chk_key).digest()[:4]).decode()
                                        vrf_res = "OK" if p_hashx == m_hashx else "ERR"
                                        snd_cmd(send_id, vrf_res)
                                        if actpeer == send_id and curr_ui == "chat":
                                            show_ui()
                                        
                                    elif cmd_ctx in ["OK", "ERR"]:
                                        alr_txt = "[+] Auto-check OK! Important to know: This check is in-band and can be simulated by an active MITM! Always compare words manually!" if cmd_ctx == "OK" else "[!] DANGER! Encryption mismatch! MITM possible!"
                                        addhist(send_id, "System", alr_txt)
                                        
                                        if cmd_ctx == "ERR":
                                            show_ui()
                                            sys.stdout.write(f"\n{clr_red}[!] Crit*: Key mismatch! MITM Attack active on channel! Disconnecting...{clr_rst}\n")
                                            sys.stdout.flush()
                                            disc_nd()
                                            break
                                            
                                        if actpeer == send_id and curr_ui == "chat":
                                            show_ui()
                                    continue
                                    
                                elif con_typ == "file":
                                    b64_dat = metadat["d"].split(",")[1]
                                    fil_byt = base64.b64decode(b64_dat)
                                    raw_nam = os.path.basename(metadat["n"].replace('\\', '/'))
                                    saf_nam = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', raw_nam)
                                    tgt_pth = os.path.join(down_dr, saf_nam)
                                    with open(tgt_pth, "wb") as fil_hnd:
                                        fil_hnd.write(fil_byt)
                                    con_str = f"{saf_nam} (Saved to downloads)"
                                    is_file = True
                                else:
                                    con_str = metadat["c"]
                                    is_file = False
                                    
                                addhist(send_id, send_id, con_str, is_file)
                                
                                if actpeer == send_id and curr_ui == "chat":
                                    show_ui()
                                else:
                                    sys.stdout.write(f"\r\033[K{clryllw}[!] New message from {send_id}{clr_rst}\n> ")
                                    sys.stdout.flush()
        except Exception:
            pass
            
        if app_cfg.get("active"):
            nod_sck = None
            sess_id = None
            if curr_ui != "main":
                sys.stdout.write(f"\r\033[K{clr_red}[!] Connection lost. Reconnecting...{clr_rst}\n> ")
                sys.stdout.flush()
            await asyncio.sleep(3)

def conn_pr(peer_id):
    if peer_id in chats_s or not nod_sck:
        return
        
    eph_key = x25519.X25519PrivateKey.generate()
    chats_s[peer_id] = {
        "stat_us": "connecting",
        "prv_key": eph_key,
        "key_val": None,
        "tx_stat": 0,
        "rx_stat": 0,
        "skip_ks": {}
    }
    
    pubbyts = eph_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pubbyts).decode()
    
    sig_val = my_ed_priv.sign(pubbyts)
    ed_pub_b64 = base64.b64encode(my_ed_pub).decode()
    sig_b64 = base64.b64encode(sig_val).decode()
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"HELO:{pub_b64}:{ed_pub_b64}:{sig_b64}"}).encode()
    asyncio.run_coroutine_threadsafe(nod_sck.send_packet(payload), evt_lop)

def snd_cmd(peer_id, cmd_txt):
    if peer_id not in chats_s or chats_s[peer_id]["stat_us"] != "secured" or not nod_sck:
        return
        
    enc_hdr, enc_dat = encrypt(chats_s[peer_id], "cmd", cmd_txt)
    cip_b64 = base64.b64encode(enc_dat).decode()
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"MSG:{enc_hdr}:{cip_b64}"}).encode()
    asyncio.run_coroutine_threadsafe(nod_sck.send_packet(payload), evt_lop)

def snd_txt(peer_id, txt_con):
    if peer_id not in chats_s or chats_s[peer_id]["stat_us"] != "secured" or not nod_sck:
        return
        
    enc_hdr, enc_dat = encrypt(chats_s[peer_id], "txt", txt_con)
    cip_b64 = base64.b64encode(enc_dat).decode()
    
    addhist(peer_id, sess_id, txt_con, False)
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"MSG:{enc_hdr}:{cip_b64}"}).encode()
    asyncio.run_coroutine_threadsafe(nod_sck.send_packet(payload), evt_lop)

def snd_fil(peer_id, fil_pth):
    if peer_id not in chats_s or chats_s[peer_id]["stat_us"] != "secured" or not nod_sck or not os.path.exists(fil_pth):
        return
    if peer_id not in verified_peers:
        return
        
    fil_nam = os.path.basename(fil_pth)
    with open(fil_pth, "rb") as fil_hnd:
        fil_b64 = base64.b64encode(fil_hnd.read()).decode()
        
    enc_hdr, enc_dat = encrypt(chats_s[peer_id], "file", (fil_nam, f"b64,{fil_b64}"))
    cip_b64 = base64.b64encode(enc_dat).decode()
    
    addhist(peer_id, sess_id, fil_nam, True)
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"MSG:{enc_hdr}:{cip_b64}"}).encode()
    asyncio.run_coroutine_threadsafe(nod_sck.send_packet(payload), evt_lop)

def make_nd():
    clear_screen()
    print(f"{clrblue}--- CREATE OWN NODE ---{clr_rst}\n")
    
    win_scr = f"""@echo off
echo [*] Opening Firewall...
netsh advfirewall firewall add rule name="Nios Node" dir=in action=allow protocol=TCP localport=7234
echo [*] Installing Dependencies...
pip install cryptography
echo [*] Generating Server Script...
python -c "import base64; open('server.py', 'wb').write(base64.b64decode('{srv_b64}'))"
echo [*] Launching Node...
python server.py
pause"""

    lin_scr = f"""#!/bin/bash
echo "[*] Opening Firewall..."
sudo ufw allow 7234/tcp || sudo iptables -A INPUT -p tcp --dport 7234 -j ACCEPT
echo "[*] Installing Dependencies..."
sudo apt-get update && sudo apt-get install -y python3-pip || true
pip3 install cryptography --break-system-packages 2>/dev/null || pip3 install cryptography
echo "[*] Generating Server Script..."
python3 -c "import base64; open('server.py', 'wb').write(base64.b64decode('{srv_b64}'))"
echo "[*] Launching Node..."
python3 server.py"""

    try:
        with open(os.path.join(basedir, "deploy_win.bat"), "w") as fil_hnd:
            fil_hnd.write(win_scr)
        with open(os.path.join(basedir, "deploy_lin.sh"), "w") as fil_hnd:
            fil_hnd.write(lin_scr)
            
        if os.name != 'nt':
            os.chmod(os.path.join(basedir, "deploy_lin.sh"), 0o755)
            
        print(f"{clrgren}[+] Export successful. Scripts saved to your PC.{clr_rst}")
        print(f" -> deploy_win.bat (Windows)")
        print(f" -> deploy_lin.sh  (Linux)")
    except Exception as err_exc:
        print(f"{clr_red}[!] Export failed: {err_exc}{clr_rst}")
        
    input("\nPress Enter to return...")

def inp_hnd():
    global actpeer, verified_peers
    usr_inp = input().strip()
    
    if usr_inp in ["/b", "/back"]:
        actpeer = None
        return
        
    if not usr_inp:
        sys.stdout.write(f"\033[1A\033[K> ")
        sys.stdout.flush()
        return
        
    if actpeer in chats_s and chats_s[actpeer]["stat_us"] == "compromised":
        sys.stdout.write(f"\033[1A\033[K{clr_red}[System]: transmission declined. Peer's key has changed! Active MITM attack suspected.{clr_rst}\n> ")
        sys.stdout.flush()
        return
        
    pr_stat = chats_s[actpeer]["stat_us"]
    if pr_stat != "secured":
        sys.stdout.write(f"\033[1A\033[K{clr_red}[System]: Connection not secured yet. Please wait.{clr_rst}\n> ")
        sys.stdout.flush()
        return
        
    if usr_inp in ["/verify", "/approve"]:
        if actpeer in verified_peers:
            sys.stdout.write(f"\033[1A\033[K{clrgren}[System]: Peer is already verified.{clr_rst}\n> ")
            sys.stdout.flush()
            return
            
        peer_sess = chats_s.get(actpeer)
        if not peer_sess or peer_sess.get("stat_us") != "secured":
            sys.stdout.write(f"\033[1A\033[K{clr_red}[System]: Cannot verify an unsecured chat.{clr_rst}\n> ")
            sys.stdout.flush()
            return
            
        peer_static_key = peer_sess.get("peer_static_ed")
        if peer_static_key:
            verified_peers[actpeer] = peer_static_key
            app_cfg["verified_encrypted"] = encrypt_verified_data(verified_peers)
            savecfg()
            addhist(actpeer, "System", "Peer verified. All restrictions lifted.")
            show_ui()
        return
        
    elif usr_inp == "/check_enc":
        addhist(actpeer, "System", "[*] Initiating auto-check...")
        addhist(actpeer, "System", "WARNING: This auto-check is in-band and can be simulated by an active MITM!")
        addhist(actpeer, "System", "Always manually compare the words below via an out-of-band channel!")
        show_ui()
        m_hashx = base64.b64encode(hashlib.sha256(chats_s[actpeer]["key_val"]).digest()[:4]).decode()
        snd_cmd(actpeer, f"CHK:{m_hashx}")
        
    elif usr_inp.startswith("/f ") or usr_inp.startswith("/file "):
        if actpeer not in verified_peers:
            sys.stdout.write(f"\033[1A\033[K{clr_red}[System]: File transfer is blocked in unverified chats. Type /verify to confirm keys.{clr_rst}\n> ")
            sys.stdout.flush()
            return
            
        fil_pth = usr_inp.split(" ", 1)[1].strip()
        if os.path.exists(fil_pth):
            snd_fil(actpeer, fil_pth)
            show_ui()
        else:
            sys.stdout.write(f"\033[1A\033[K{clr_red}[System]: File not found.{clr_rst}\n> ")
            sys.stdout.flush()
            
    else:
        snd_txt(actpeer, usr_inp)
        show_ui()

def mainlop():
    global actpeer, sess_id, curr_ui, verified_peers
    loadcfg()
    
    while True:
        curr_ui = "main"
        clear_screen()
        print(f"{clrblue}{clrbold}--- e2e manager ---{clr_rst}")
        print(f"Downloads: {down_dr}\n")
        print("1. Connect to Node")
        print("2. Connect in Full Anonymous Mode (fam)")
        print("3. Create own node")
        print("4. Exit")
        
        sav_nod = f"{app_cfg.get('host')}:{app_cfg.get('port')}" if app_cfg.get("host") else ""
        if sav_nod and not app_cfg.get("active") and not app_cfg.get("anon_mode"):
            print(f"\n{clrgren}[*] Saved node: {sav_nod}{clr_rst}")
            
        mnu_chc = input("\n> ").strip()
        
        if mnu_chc in ["1", "2"]:
            is_anon = (mnu_chc == "2")
            clear_screen()
            print(f"{clr_red}{clrbold}--- SECURITY WARNING ---{clr_rst}")
            print("Intermediate nodes route your E2E traffic. They can see:")
            print(" - Your IP address and the IP of your peer")
            print(" - Exact timestamps and sizes of all messages")
            print(f"{clryllw}CRITICAL: Only connect to trusted nodes or deploy your own!{clr_rst}\n")
            
            if is_anon:
                print(f"{clrmgnt}[*] fam (experimental): Ephemeral identity, no logs, no saved IP.{clr_rst}\n")
            
            if app_cfg.get("host") and not is_anon:
                print(f"Saved Node: {app_cfg['host']}:{app_cfg['port']}")
                if input("Use saved node? (y/n): ").strip().lower() != 'y':
                    app_cfg["host"] = input("Host: ").strip()
                    prt_inp = input("Port [7234]: ").strip()
                    app_cfg["port"] = int(prt_inp) if prt_inp else 7234
                    app_cfg["key"] = input("Access Key: ").strip()
            else:
                app_cfg["host"] = input("Host: ").strip()
                prt_inp = input("Port [7234]: ").strip()
                app_cfg["port"] = int(prt_inp) if prt_inp else 7234
                app_cfg["key"] = input("Access Key: ").strip()
                
            app_cfg["active"] = True
            app_cfg["anon_mode"] = is_anon
            if not is_anon:
                savecfg()
            
            print(f"{clryllw}Establishing secure socket...{clr_rst}")
            tm_cntr = 10.0
            while tm_cntr > 0 and not sess_id and app_cfg["active"]:
                time.sleep(0.5)
                tm_cntr -= 0.5
                
            if not sess_id:
                print(f"{clr_red}Connection failed.{clr_rst}")
                disc_nd()
                time.sleep(2.0)
                continue
                
            while app_cfg["active"]:
                if actpeer:
                    curr_ui = "chat"
                    time.sleep(0.5)
                    continue
                    
                curr_ui = "session"
                clear_screen()
                print(f"{clrblue}--- Menu ---{clr_rst}")
                if is_anon:
                    print(f"Your ID: {clrmgnt}{sess_id} (is anonymous){clr_rst}\n")
                else:
                    print(f"Your ID: {clrgren}{sess_id}{clr_rst}\n")
                print("1. New Chat (Connect to Peer)")
                print("2. Active Chats")
                print("3. Check Encryption")
                print("4. Disconnect Node")
                
                ses_chc = input("\n> ").strip()
                
                if ses_chc == "1":
                    peer_in = input("Enter PeerID: ").strip().upper()
                    if len(peer_in) in [6, 16]:
                        conn_pr(peer_in)
                        actpeer = peer_in
                        curr_ui = "chat"
                        show_ui()
                        while actpeer and app_cfg["active"]:
                            inp_hnd()
                                
                elif ses_chc == "2":
                    while True:
                        curr_ui = "session"
                        clear_screen()
                        print(f"{clrblue}--- Chats ---{clr_rst}")
                        ses_key = list(chats_s.keys())
                        
                        if not ses_key:
                            print("No active chats.")
                            
                        for idx_val, peer_id in enumerate(ses_key):
                            is_verified = peer_id in verified_peers
                            status_lbl = f"{clrgren}[Verified]{clr_rst}" if is_verified else f"{clryllw}[Unverified]{clr_rst}"
                            
                            pr_stat = "Secured" if chats_s[peer_id]["stat_us"] == "secured" else "Connecting"
                            if chats_s[peer_id]["stat_us"] == "compromised":
                                pr_stat = f"{clr_red}BLOCKED/MITM{clr_rst}"
                                
                            print(f"{idx_val}. {peer_id} {status_lbl} [{pr_stat}]")
                            
                        sel_val = input("\nEnter number to open chat, or 'b' to go back: ").strip()
                        if sel_val.lower() == 'b':
                            break
                            
                        if sel_val.isdigit() and int(sel_val) < len(ses_key):
                            actpeer = ses_key[int(sel_val)]
                            curr_ui = "chat"
                            show_ui()
                            while actpeer and app_cfg["active"]:
                                inp_hnd()
                                    
                elif ses_chc == "3":
                    while True:
                        clear_screen()
                        print(f"{clrblue}--- Verify Encryption ---{clr_rst}")
                        sec_cht = [peer_id for peer_id, session_data in chats_s.items() if session_data["stat_us"] == "secured"]
                        
                        if not sec_cht:
                            print("No secured chats available.")
                            input("\nPress Enter to return...")
                            break
                            
                        for idx_val, peer_id in enumerate(sec_cht):
                            print(f"{idx_val}. {peer_id}")
                            
                        sel_val = input("\nSelect chat to verify, or 'b' to go back: ").strip()
                        if sel_val.lower() == 'b':
                            break
                            
                        if sel_val.isdigit() and int(sel_val) < len(sec_cht):
                            cho_pee = sec_cht[int(sel_val)]
                            clear_screen()
                            print(f"{clrblue}--- Audit: {cho_pee} ---{clr_rst}\n")
                            
                            print(f"{clryllw}Visual Session Signature (Visual Key Words):{clr_rst}")
                            print(f"  {get_wrd(chats_s[cho_pee]['key_val'])}\n")
                            
                            peer_static_hex = base64.b64decode(chats_s[cho_pee]['peer_static_ed']).hex().upper()
                            peer_formatted = " ".join(peer_static_hex[i:i+4] for i in range(0, len(peer_static_hex), 4))
                            print(f"{clryllw}Peer Static Ed25519 Fingerprint:{clr_rst}")
                            print(f"  {peer_formatted}\n")
                            
                            my_static_hex = my_ed_pub.hex().upper()
                            my_formatted = " ".join(my_static_hex[i:i+4] for i in range(0, len(my_static_hex), 4))
                            print(f"{clryllw}Your Own Static Ed25519 Fingerprint:{clr_rst}")
                            print(f"  {my_formatted}\n")
                            
                            sess_hash = hashlib.sha256(chats_s[cho_pee]['key_val']).digest().hex().upper()
                            sess_formatted = " ".join(sess_hash[i:i+4] for i in range(0, len(sess_hash), 4))
                            print(f"{clryllw}Current Session Key Hash:{clr_rst}")
                            print(f"  {sess_formatted}\n")
                            
                            print(f"{clr_red}INSTRUCTION FOR PARANOIDS:{clr_rst}")
                            print("1. Match the sequence of 4 words and colors. They must be identical.")
                            print("2. Compare the peer's Fingerprint with their actual key via a trusted channel.")
                            print("3. Any mismatch means the server or network is compromised (MITM).")
                            print("4. If everything matches, type /verify inside the chat with the peer.\n")
                            input("Press Enter to return...")
                            
                elif ses_chc == "4":
                    disc_nd()
                    
        elif mnu_chc == "3":
            make_nd()
        elif mnu_chc == "4":
            disc_nd()
            sys.exit(0)

def run_thr(lop_ins):
    asyncio.set_event_loop(lop_ins)
    lop_ins.create_task(socklop())
    lop_ins.run_forever()

if __name__ == "__main__":
    evt_lop = asyncio.new_event_loop()
    threading.Thread(target=run_thr, args=(evt_lop,), daemon=True).start()
    mainlop()
