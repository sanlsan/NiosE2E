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

base_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
download_dir = os.path.join(base_dir, "downloads")
os.makedirs(download_dir, exist_ok=True)
config_path = os.path.join(base_dir, "config.json")

color_blue = "\033[94m"
color_green = "\033[92m"
color_red = "\033[91m"
color_yellow = "\033[93m"
color_cyan = "\033[96m"
color_magenta = "\033[95m"
color_white = "\033[97m"
color_bold = "\033[1m"
color_reset = "\033[0m"

cl_ls = [color_red, color_green, color_yellow, color_blue, color_magenta, color_cyan, color_white]

server_source = """import asyncio, os, base64, json, secrets
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hkdf_derive(salt_bytes, material_bytes, info_bytes):
    return HKDF(SHA256(), 32, salt_bytes, info_bytes).derive(material_bytes)

def encrypt_aead(encryption_key, data_bytes, ad=None):
    aesgcm = AESGCM(encryption_key)
    initialization_vector = os.urandom(12)
    return initialization_vector + aesgcm.encrypt(initialization_vector, data_bytes, ad)

def decrypt_aead(encryption_key, cipher_payload, ad=None):
    try:
        return AESGCM(encryption_key).decrypt(cipher_payload[:12], cipher_payload[12:], ad)
    except:
        return None

class ServerNodeSession:
    def __init__(self, reader, writer, static_key):
        self.reader = reader
        self.writer = writer
        self.static_key = static_key
        self.session_key = None
        self.ephemeral_key = x25519.X25519PrivateKey.generate()

    async def handshake(self):
        client_public_bytes = await self.reader.readexactly(32)
        client_public_key = x25519.X25519PublicKey.from_public_bytes(client_public_bytes)
        shared_secret1 = self.static_key.exchange(client_public_key)
        handshake_key = hkdf_derive(None, shared_secret1, b"NiosHandshake")
        shared_secret2 = self.ephemeral_key.exchange(client_public_key)
        self.session_key = hkdf_derive(None, shared_secret1 + shared_secret2, b"NiosSocket")
        ephemeral_public_bytes = self.ephemeral_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.writer.write(encrypt_aead(handshake_key, ephemeral_public_bytes))
        await self.writer.drain()

    async def send_packet(self, data_payload):
        encrypted_payload = encrypt_aead(self.session_key, data_payload)
        self.writer.write(len(encrypted_payload).to_bytes(4, 'big') + encrypted_payload)
        await self.writer.drain()

    async def receive_packet(self):
        length_bytes = await self.reader.readexactly(4)
        payload_length = int.from_bytes(length_bytes, 'big')
        encrypted_payload = await self.reader.readexactly(payload_length)
        decrypted_payload = decrypt_aead(self.session_key, encrypted_payload)
        if not decrypted_payload:
            raise ConnectionError("Server session AEAD validation failed.")
        return decrypted_payload

clients_dict = {}
users_db_path = "users.json"

def load_users():
    if os.path.exists(users_db_path):
        with open(users_db_path, "r") as f:
            return json.load(f)
    return {}

def save_users(db):
    with open(users_db_path, "w") as f:
        json.dump(db, f)

async def handle_connection(reader, writer, static_key):
    session = ServerNodeSession(reader, writer, static_key)
    try:
        await session.handshake()
    except:
        return writer.close()
    
    try:
        auth_req = await session.receive_packet()
        auth_data = json.loads(auth_req.decode())
        if auth_data.get("action") != "auth": raise Exception()
        peer_id = auth_data["peer_id"]
        pub_b64 = auth_data["pub"]
        
        db = load_users()
        if peer_id not in db:
            db[peer_id] = pub_b64
            save_users(db)
        elif db[peer_id] != pub_b64:
            raise Exception()
            
        chal = os.urandom(32).hex()
        await session.send_packet(json.dumps({"type": "challenge", "data": chal}).encode())
        
        resp_req = await session.receive_packet()
        resp_data = json.loads(resp_req.decode())
        if resp_data.get("action") != "auth_resp": raise Exception()
        
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub_key.verify(bytes.fromhex(resp_data["sig"]), bytes.fromhex(chal))
        
        session_id = peer_id
        clients_dict[session_id] = session
        print(f"[+] Client connected: {session_id}")
        
        await session.send_packet(json.dumps({"type": "system", "text": f"Session ID:{session_id}"}).encode())
        while True:
            received_data = await session.receive_packet()
            data_json = json.loads(received_data.decode())
            if data_json.get("action") == "send":
                target_peer = data_json.get("to")
                message_text = data_json.get("text")
                if target_peer in clients_dict:
                    await clients_dict[target_peer].send_packet(json.dumps({"type": "message", "from": session_id, "text": message_text}).encode())
    except Exception as e:
        pass
    finally:
        if 'session_id' in locals() and session_id in clients_dict:
            clients_dict.pop(session_id, None)
            print(f"[-] Client disconnected: {session_id}")
        writer.close()

async def run_server():
    key_file = "server.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            static_key = x25519.X25519PrivateKey.from_private_bytes(f.read())
    else:
        static_key = x25519.X25519PrivateKey.generate()
        with open(key_file, "wb") as f:
            f.write(static_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
            
    public_key_bytes = static_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    server = await asyncio.start_server(lambda r, w: handle_connection(r, w, static_key), '0.0.0.0', 7234)
    print(f"PORT: 7234\\nACCESS KEY: {public_key_b64}\\n")
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(run_server())"""

server_b64 = base64.b64encode(server_source.encode()).decode()

def dbg_ck():
    if sys.gettrace() is not None:
        return True
    try:
        import ctypes
        if os.name == 'nt' and ctypes.windll.kernel32.IsDebuggerPresent():
            return True
    except:
        pass
    try:
        if os.name == 'posix' and os.path.exists('/proc/self/status'):
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith("TracerPid:") and int(line.split()[1]) != 0:
                        return True
    except:
        pass
    return False

def secure_exit():
    ds_nd()
    sys.exit(0)

def hkdf_derive(salt_bytes, material_bytes, info_bytes):
    return HKDF(SHA256(), 32, salt_bytes, info_bytes).derive(material_bytes)

def KDF_RK(rk, dh_out):
    hkdf = HKDF(SHA256(), 64, rk, b"KDF_RK")
    out = hkdf.derive(dh_out)
    return out[:32], out[32:]

def KDF_CK(ck):
    hkdf = HKDF(SHA256(), 64, None, b"KDF_CK")
    out = hkdf.derive(ck)
    return out[:32], out[32:]

def encrypt_aead(encryption_key, data_bytes, ad=None):
    aesgcm = AESGCM(encryption_key)
    initialization_vector = os.urandom(12)
    return initialization_vector + aesgcm.encrypt(initialization_vector, data_bytes, ad)

def decrypt_aead(encryption_key, cipher_payload, ad=None):
    try:
        return AESGCM(encryption_key).decrypt(cipher_payload[:12], cipher_payload[12:], ad)
    except:
        return None

def gt_wd(k_byt):
    if not k_byt:
        return ""
    dg_by = hashlib.sha256(k_byt).digest()
    w_lst = [
        "acid", "apex", "band", "bark", "beta", "bolt", "born", "calm", "clay", "coal",
        "dark", "dawn", "echo", "edge", "envy", "fade", "film", "flow", "flux", "glow",
        "grid", "hawk", "haze", "hint", "icon", "iron", "jade", "jolt", "kept", "lava",
        "leaf", "limo", "maze", "mist", "neon", "node", "opal", "open", "path", "pave",
        "rift", "rust", "sand", "silk", "spark", "tide", "toad", "volt", "wave", "zinc"
    ]
    el_ms = []
    for idx in range(4):
        w_idx = dg_by[idx * 2] % 50
        c_idx = dg_by[idx * 2 + 1] % len(cl_ls)
        word = w_lst[w_idx]
        colr = cl_ls[c_idx]
        el_ms.append(f"{colr}{word}{color_reset}")
    return " | ".join(el_ms)

def skip_message_keys(sess, until):
    if sess["Nr"] + 100 < until:
        raise ConnectionError("Too many skipped messages")
    if sess["CKr"] is not None:
        while sess["Nr"] < until:
            sess["CKr"], mk = KDF_CK(sess["CKr"])
            sess["sk_ks"][f"{sess['DHr']}_{sess['Nr']}"] = mk
            sess["Nr"] += 1

def DHRatchet(sess, header):
    sess["PN"] = sess["Ns"]
    sess["Ns"] = 0
    sess["Nr"] = 0
    sess["DHr"] = header["dh"]
    dh_r_bytes = base64.b64decode(sess["DHr"])
    dh_r_key = x25519.X25519PublicKey.from_public_bytes(dh_r_bytes)
    sess["RK"], sess["CKr"] = KDF_RK(sess["RK"], sess["DHs"].exchange(dh_r_key))
    sess["DHs"] = x25519.X25519PrivateKey.generate()
    sess["RK"], sess["CKs"] = KDF_RK(sess["RK"], sess["DHs"].exchange(dh_r_key))

def enc_r(sess, t_yp, cont):
    if dbg_ck(): secure_exit()
    sess["CKs"], mk = KDF_CK(sess["CKs"])
    dh_pub = sess["DHs"].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    header = {
        "dh": base64.b64encode(dh_pub).decode(),
        "pn": sess["PN"],
        "n": sess["Ns"]
    }
    sess["Ns"] += 1
    meta = {"t": t_yp}
    if t_yp == "file":
        meta["n"] = cont[0]
        meta["d"] = cont[1]
    else:
        meta["c"] = cont
    pad_len = secrets.randbelow(113) + 16
    meta["p"] = secrets.token_hex(pad_len // 2)
    
    header_b64 = base64.b64encode(json.dumps(header).encode()).decode()
    header_bytes = base64.b64decode(header_b64)
    enc_d = encrypt_aead(mk, json.dumps(meta).encode(), header_bytes)
    
    c1 = sess.get("CKs") or b""
    c2 = sess.get("CKr") or b""
    sess["key"] = hkdf_derive(None, min(c1, c2) + max(c1, c2), b"Visual")
    gc.collect()
    return header_b64, enc_d

def dec_r(sess, header_b64, ciph):
    if dbg_ck(): secure_exit()
    header_bytes = base64.b64decode(header_b64)
    header = json.loads(header_bytes.decode())
    
    mk_key = f"{header['dh']}_{header['n']}"
    if mk_key in sess["sk_ks"]:
        mk = sess["sk_ks"].pop(mk_key)
        plain = decrypt_aead(mk, ciph, header_bytes)
        gc.collect()
        return plain

    temp_sess = {
        "RK": sess["RK"],
        "CKs": sess["CKs"],
        "CKr": sess["CKr"],
        "Ns": sess["Ns"],
        "Nr": sess["Nr"],
        "PN": sess["PN"],
        "DHr": sess["DHr"],
        "DHs": sess["DHs"],
        "sk_ks": sess["sk_ks"].copy(),
        "key": sess["key"]
    }

    try:
        if header["dh"] != temp_sess["DHr"]:
            skip_message_keys(temp_sess, header["pn"])
            DHRatchet(temp_sess, header)
        
        skip_message_keys(temp_sess, header["n"])
        temp_sess["CKr"], mk = KDF_CK(temp_sess["CKr"])
        temp_sess["Nr"] += 1
        
        plain = decrypt_aead(mk, ciph, header_bytes)
        if plain is not None:
            for k in temp_sess:
                sess[k] = temp_sess[k]
            sess["prev_key"] = sess["key"]
            c1 = sess.get("CKs") or b""
            c2 = sess.get("CKr") or b""
            sess["key"] = hkdf_derive(None, min(c1, c2) + max(c1, c2), b"Visual")
            gc.collect()
            return plain
        return None
    except Exception:
        return None

class ClientSocket:
    def __init__(self, reader, writer, access_key):
        self.reader = reader
        self.writer = writer
        self.access_key = access_key
        self.session_key = None
        self.private_key = x25519.X25519PrivateKey.generate()

    async def handshake(self):
        public_bytes = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.writer.write(public_bytes)
        await self.writer.drain()
        
        response = await self.reader.readexactly(60)
        server_public_key = x25519.X25519PublicKey.from_public_bytes(self.access_key)
        shared_key1 = self.private_key.exchange(server_public_key)
        handshake_key = hkdf_derive(None, shared_key1, b"NiosHandshake")
        
        decrypted_bytes = decrypt_aead(handshake_key, response)
        if not decrypted_bytes:
            raise ConnectionError("Handshake AEAD decryption failed.")
            
        ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(decrypted_bytes)
        shared_key2 = self.private_key.exchange(ephemeral_public_key)
        self.session_key = hkdf_derive(None, shared_key1 + shared_key2, b"NiosSocket")
        gc.collect()

    async def send_packet(self, data_payload):
        encrypted_payload = encrypt_aead(self.session_key, data_payload)
        self.writer.write(len(encrypted_payload).to_bytes(4, 'big') + encrypted_payload)
        await self.writer.drain()

    async def receive_packet(self):
        length_bytes = await self.reader.readexactly(4)
        payload_length = int.from_bytes(length_bytes, 'big')
        encrypted_payload = await self.reader.readexactly(payload_length)
        decrypted_payload = decrypt_aead(self.session_key, encrypted_payload)
        if not decrypted_payload:
            raise ConnectionError("Socket AEAD validation failed.")
        return decrypted_payload

node_socket = None
session_id = None
active_peer = None
event_loop = None
chat_sessions = {}
message_history = {}
current_ui = "main"
app_config = {"host": None, "port": None, "key": None, "active": False, "anon_mode": False}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_config():
    global app_config
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as config_file:
                app_config.update(json.load(config_file))
        except:
            pass

def save_config():
    with open(config_path, "w") as config_file:
        json.dump({k: v for k, v in app_config.items() if k not in ["active", "anon_mode"]}, config_file)

def get_node_auth(host, port, is_anon):
    if is_anon:
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        peer_id = hashlib.sha256(pub_bytes).digest()[:8].hex().upper()
        return priv, base64.b64encode(pub_bytes).decode(), peer_id

    node_key = f"{host}:{port}"
    if "nodes" not in app_config:
        app_config["nodes"] = {}
    if node_key not in app_config["nodes"]:
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        app_config["nodes"][node_key] = base64.b64encode(priv_bytes).decode()
        save_config()
    
    priv_bytes = base64.b64decode(app_config["nodes"][node_key])
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    peer_id = hashlib.sha256(pub_bytes).digest()[:8].hex().upper()
    return priv, base64.b64encode(pub_bytes).decode(), peer_id

def ds_nd():
    global node_socket, session_id
    is_anon = app_config.get("anon_mode", False)
    app_config["active"] = False
    if node_socket:
        try:
            node_socket.writer.close()
        except:
            pass
        node_socket = None
    session_id = None
    chat_sessions.clear()
    message_history.clear()
    if is_anon:
        app_config["host"] = None
        app_config["port"] = None
        app_config["key"] = None
        app_config["anon_mode"] = False
    gc.collect()

def render_chat_ui():
    if not active_peer:
        return
        
    clear_screen()
    wds_s = gt_wd(chat_sessions[active_peer]["key"]) if active_peer in chat_sessions and chat_sessions[active_peer]["status"] == "secured" else ""
    
    print(f"{color_blue}{color_bold}--- CHAT: {active_peer} ---{color_reset}")
    if wds_s:
        print(f" Key: {wds_s}\n")
    print(f"{color_yellow}Commands: /b (back) | /f <path> | /check_enc{color_reset}\n")
    
    for message in message_history.get(active_peer, []):
        sender = message["from"]
        if sender == session_id:
            name_tag = "You"
            name_color = color_green
        elif sender == "System":
            name_tag = "System"
            name_color = color_yellow
        else:
            name_tag = "Opponent"
            name_color = color_cyan
            
        if message["is_file"]:
            print(f"{name_color}[{name_tag}]:{color_reset} {color_yellow}[FILE: {message['content']}]{color_reset}")
        else:
            print(f"{name_color}[{name_tag}]:{color_reset} {message['content']}")
            
    print(f"\n{color_bold}>{color_reset} ", end="")
    sys.stdout.flush()

def add_history_message(peer_id, sender_id, message_content, is_file=False):
    if peer_id not in message_history:
        message_history[peer_id] = []
    message_history[peer_id].append({"from": sender_id, "content": message_content, "is_file": is_file})

async def listen_socket_loop():
    global node_socket, session_id, chat_sessions, message_history
    
    while True:
        if dbg_ck(): secure_exit()
            
        if not app_config.get("active"):
            if node_socket:
                try: node_socket.writer.close()
                except: pass
                node_socket = None
            await asyncio.sleep(0.5)
            continue
            
        try:
            reader, writer = await asyncio.open_connection(app_config["host"], app_config["port"])
            decoded_key = base64.b64decode(app_config["key"])
            socket_session = ClientSocket(reader, writer, decoded_key)
            await socket_session.handshake()
            node_socket = socket_session
            
            ed_priv, ed_pub_b64, p_id = get_node_auth(app_config["host"], app_config["port"], app_config.get("anon_mode", False))
            await node_socket.send_packet(json.dumps({"action": "auth", "peer_id": p_id, "pub": ed_pub_b64}).encode())
            
            chal_pkt = await node_socket.receive_packet()
            chal_data = json.loads(chal_pkt.decode())
            if chal_data.get("type") != "challenge": raise Exception()
            
            sig = ed_priv.sign(bytes.fromhex(chal_data["data"]))
            await node_socket.send_packet(json.dumps({"action": "auth_resp", "sig": sig.hex()}).encode())
            
            sys_pkt = await node_socket.receive_packet()
            sys_data = json.loads(sys_pkt.decode())
            if "ID" in sys_data.get("text", ""):
                session_id = sys_data["text"].split(":")[-1].strip()
            
            while app_config.get("active"):
                if dbg_ck(): secure_exit()
                    
                packet_bytes = await node_socket.receive_packet()
                if not packet_bytes:
                    break
                    
                payload_json = json.loads(packet_bytes.decode())
                message_type = payload_json.get("type")
                
                if message_type == "system":
                    continue
                    
                elif message_type == "message":
                    sender_id = payload_json.get("from")
                    message_text = payload_json.get("text", "")
                    
                    if message_text.startswith("HELO:"):
                        peer_public_bytes = base64.b64decode(message_text.split(":", 1)[1])
                        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
                        my_private_key = x25519.X25519PrivateKey.generate()
                        my_public_bytes = my_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                        my_public_b64 = base64.b64encode(my_public_bytes).decode()
                        
                        SK = my_private_key.exchange(peer_public_key)
                        RK = SK
                        RK, CKr = KDF_RK(RK, SK)
                        DHs = x25519.X25519PrivateKey.generate()
                        DHr = base64.b64encode(peer_public_bytes).decode()
                        RK, CKs = KDF_RK(RK, DHs.exchange(peer_public_key))
                        
                        chat_sessions[sender_id] = {
                            "status": "secured",
                            "DHs": DHs,
                            "DHr": DHr,
                            "RK": RK,
                            "CKs": CKs,
                            "CKr": CKr,
                            "Ns": 0,
                            "Nr": 0,
                            "PN": 0,
                            "sk_ks": {},
                            "key": hkdf_derive(None, min(CKs, CKr) + max(CKs, CKr), b"Visual"),
                            "prev_key": None
                        }
                        
                        response_payload = json.dumps({"action": "send", "to": sender_id, "text": f"RESP:{my_public_b64}"})
                        await node_socket.send_packet(response_payload.encode())
                        
                        wds_s = gt_wd(chat_sessions[sender_id]["key"])
                        system_msg = f"Chat established. Secure Key: {wds_s}"
                        add_history_message(sender_id, "System", system_msg)
                        
                        if active_peer == sender_id and current_ui == "chat":
                            render_chat_ui()
                        elif current_ui != "main":
                            sys.stdout.write(f"\r\033[K{color_green}[+] Secure Chat established with {sender_id}{color_reset}\n> ")
                            sys.stdout.flush()
                            
                    elif message_text.startswith("RESP:"):
                        if sender_id in chat_sessions and chat_sessions[sender_id]["status"] == "connecting":
                            peer_public_bytes = base64.b64decode(message_text.split(":", 1)[1])
                            peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
                            my_private_key = chat_sessions[sender_id]["priv"]
                            
                            SK = my_private_key.exchange(peer_public_key)
                            RK = SK
                            DHs = my_private_key
                            DHr = base64.b64encode(peer_public_bytes).decode()
                            RK, CKs = KDF_RK(RK, SK)
                            CKr = None
                            
                            chat_sessions[sender_id] = {
                                "status": "secured",
                                "DHs": DHs,
                                "DHr": DHr,
                                "RK": RK,
                                "CKs": CKs,
                                "CKr": CKr,
                                "Ns": 0,
                                "Nr": 0,
                                "PN": 0,
                                "sk_ks": {},
                                "key": hkdf_derive(None, min(CKs, b"") + max(CKs, b""), b"Visual"),
                                "prev_key": None
                            }
                            
                            wds_s = gt_wd(chat_sessions[sender_id]["key"])
                            system_msg = f"Chat secured. Secure Key: {wds_s}"
                            add_history_message(sender_id, "System", system_msg)
                            
                            if active_peer == sender_id and current_ui == "chat":
                                render_chat_ui()
                            elif current_ui != "main":
                                sys.stdout.write(f"\r\033[K{color_green}[+] Secure Chat established with {sender_id}{color_reset}\n> ")
                                sys.stdout.flush()
                                
                    elif message_text.startswith("MSG:"):
                        parts = message_text.split(":")
                        if len(parts) == 3 and sender_id in chat_sessions and chat_sessions[sender_id]["status"] == "secured":
                            header_b64 = parts[1]
                            cipher_payload = base64.b64decode(parts[2])
                            
                            decrypted_message = dec_r(chat_sessions[sender_id], header_b64, cipher_payload)
                            
                            if not decrypted_message:
                                sys.stdout.write(f"\r\033[K{color_red}[!] CRITICAL SECURITY ALERT: E2E message decryption failed! Tampering or MITM attack detected! Instantly disconnecting...{color_reset}\n> ")
                                sys.stdout.flush()
                                ds_nd()
                                break
                            
                            metadata = json.loads(decrypted_message.decode())
                            content_type = metadata.get("t")
                            
                            if content_type == "cmd":
                                command_ctx = metadata["c"]
                                if command_ctx.startswith("CHK:"):
                                    peer_hash = command_ctx[4:]
                                    chk_k = chat_sessions[sender_id].get("prev_key") or chat_sessions[sender_id]["key"]
                                    my_hash = base64.b64encode(hashlib.sha256(chk_k).digest()[:4]).decode()
                                    verification_result = "OK" if peer_hash == my_hash else "ERR"
                                    send_internal_cmd(sender_id, verification_result)
                                    if active_peer == sender_id and current_ui == "chat":
                                        render_chat_ui()
                                    
                                elif command_ctx in ["OK", "ERR"]:
                                    alert_text = "[+] Auto-check OK! WARNING: This check is in-band and can be simulated by an active MITM! Always compare words manually!" if command_ctx == "OK" else "[!] DANGER! Encryption mismatch! MITM possible!"
                                    add_history_message(sender_id, "System", alert_text)
                                    
                                    if command_ctx == "ERR":
                                        render_chat_ui()
                                        sys.stdout.write(f"\n{color_red}[!] CRITICAL: Key mismatch! MITM Attack active on channel! Disconnecting...{color_reset}\n")
                                        sys.stdout.flush()
                                        ds_nd()
                                        break
                                        
                                    if active_peer == sender_id and current_ui == "chat":
                                        render_chat_ui()
                                continue
                                
                            elif content_type == "file":
                                b64_data = metadata["d"].split(",")[1]
                                file_bytes = base64.b64decode(b64_data)
                                raw_filename = os.path.basename(metadata["n"].replace('\\', '/'))
                                safe_filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', raw_filename)
                                target_path = os.path.join(download_dir, safe_filename)
                                with open(target_path, "wb") as file_handler:
                                    file_handler.write(file_bytes)
                                content_str = f"{safe_filename} (Saved to downloads)"
                                is_file_flag = True
                            else:
                                content_str = metadata["c"]
                                is_file_flag = False
                                
                            add_history_message(sender_id, sender_id, content_str, is_file_flag)
                            
                            if active_peer == sender_id and current_ui == "chat":
                                render_chat_ui()
                            else:
                                sys.stdout.write(f"\r\033[K{color_yellow}[!] New message from {sender_id}{color_reset}\n> ")
                                sys.stdout.flush()
        except Exception:
            pass
            
        if app_config.get("active"):
            node_socket = None
            session_id = None
            if current_ui != "main":
                sys.stdout.write(f"\r\033[K{color_red}[!] Connection lost. Reconnecting...{color_reset}\n> ")
                sys.stdout.flush()
            await asyncio.sleep(3)

def tunnel_to_peer(peer_id):
    if peer_id in chat_sessions or not node_socket:
        return
        
    ephemeral_key = x25519.X25519PrivateKey.generate()
    chat_sessions[peer_id] = {
        "status": "connecting",
        "priv": ephemeral_key,
        "key": None,
        "tx": 0,
        "rx": 0,
        "sk_ks": {}
    }
    
    public_bytes = ephemeral_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_b64 = base64.b64encode(public_bytes).decode()
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"HELO:{public_b64}"}).encode()
    asyncio.run_coroutine_threadsafe(node_socket.send_packet(payload), event_loop)

def send_internal_cmd(peer_id, cmd_text):
    if peer_id not in chat_sessions or chat_sessions[peer_id]["status"] != "secured" or not node_socket:
        return
        
    enc_h, enc_d = enc_r(chat_sessions[peer_id], "cmd", cmd_text)
    cipher_base64 = base64.b64encode(enc_d).decode()
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"MSG:{enc_h}:{cipher_base64}"}).encode()
    asyncio.run_coroutine_threadsafe(node_socket.send_packet(payload), event_loop)

def send_text_msg(peer_id, text_content):
    if peer_id not in chat_sessions or chat_sessions[peer_id]["status"] != "secured" or not node_socket:
        return
        
    enc_h, enc_d = enc_r(chat_sessions[peer_id], "txt", text_content)
    cipher_base64 = base64.b64encode(enc_d).decode()
    
    add_history_message(peer_id, session_id, text_content, False)
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"MSG:{enc_h}:{cipher_base64}"}).encode()
    asyncio.run_coroutine_threadsafe(node_socket.send_packet(payload), event_loop)

def send_file_attachment(peer_id, file_path):
    if peer_id not in chat_sessions or chat_sessions[peer_id]["status"] != "secured" or not node_socket or not os.path.exists(file_path):
        return
        
    file_name = os.path.basename(file_path)
    with open(file_path, "rb") as file_handler:
        file_b64 = base64.b64encode(file_handler.read()).decode()
        
    enc_h, enc_d = enc_r(chat_sessions[peer_id], "file", (file_name, f"b64,{file_b64}"))
    cipher_base64 = base64.b64encode(enc_d).decode()
    
    add_history_message(peer_id, session_id, file_name, True)
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"MSG:{enc_h}:{cipher_base64}"}).encode()
    asyncio.run_coroutine_threadsafe(node_socket.send_packet(payload), event_loop)

def create_own_node():
    clear_screen()
    print(f"{color_blue}--- CREATE OWN NODE ---{color_reset}\n")
    
    windows_script = f"""@echo off
echo [*] Opening Firewall...
netsh advfirewall firewall add rule name="Nios Node" dir=in action=allow protocol=TCP localport=7234
echo [*] Installing Dependencies...
pip install cryptography
echo [*] Generating Server Script...
python -c "import base64; open('server.py', 'wb').write(base64.b64decode('{server_b64}'))"
echo [*] Launching Node...
python server.py
pause"""

    linux_script = f"""#!/bin/bash
echo "[*] Opening Firewall..."
sudo ufw allow 7234/tcp || sudo iptables -A INPUT -p tcp --dport 7234 -j ACCEPT
echo "[*] Installing Dependencies..."
sudo apt-get update && sudo apt-get install -y python3-pip || true
pip3 install cryptography --break-system-packages 2>/dev/null || pip3 install cryptography
echo "[*] Generating Server Script..."
python3 -c "import base64; open('server.py', 'wb').write(base64.b64decode('{server_b64}'))"
echo "[*] Launching Node..."
python3 server.py"""

    try:
        with open(os.path.join(base_dir, "deploy_win.bat"), "w") as file_handler:
            file_handler.write(windows_script)
        with open(os.path.join(base_dir, "deploy_lin.sh"), "w") as file_handler:
            file_handler.write(linux_script)
            
        if os.name != 'nt':
            os.chmod(os.path.join(base_dir, "deploy_lin.sh"), 0o755)
            
        print(f"{color_green}[+] Export successful. Scripts saved to your PC.{color_reset}")
        print(f" -> deploy_win.bat (Windows)")
        print(f" -> deploy_lin.sh  (Linux)")
    except Exception as error_exception:
        print(f"{color_red}[!] Export failed: {error_exception}{color_reset}")
        
    input("\nPress Enter to return...")

def handle_chat_input():
    global active_peer
    user_input = input().strip()
    
    if user_input in ["/b", "/back"]:
        active_peer = None
        return
        
    if not user_input:
        sys.stdout.write(f"\033[1A\033[K> ")
        sys.stdout.flush()
        return
        
    peer_status = chat_sessions[active_peer]["status"]
    if peer_status != "secured":
        sys.stdout.write(f"\033[1A\033[K{color_red}[System]: Connection not secured yet. Please wait.{color_reset}\n> ")
        sys.stdout.flush()
        return
        
    if user_input == "/check_enc":
        add_history_message(active_peer, "System", "[*] Initiating auto-check...")
        add_history_message(active_peer, "System", "WARNING: This auto-check is in-band and can be simulated by an active MITM!")
        add_history_message(active_peer, "System", "Always manually compare the words below via an out-of-band channel!")
        render_chat_ui()
        my_hash = base64.b64encode(hashlib.sha256(chat_sessions[active_peer]["key"]).digest()[:4]).decode()
        send_internal_cmd(active_peer, f"CHK:{my_hash}")
        
    elif user_input.startswith("/f ") or user_input.startswith("/file "):
        file_path = user_input.split(" ", 1)[1].strip()
        if os.path.exists(file_path):
            send_file_attachment(active_peer, file_path)
            render_chat_ui()
        else:
            sys.stdout.write(f"\033[1A\033[K{color_red}[System]: File not found.{color_reset}\n> ")
            sys.stdout.flush()
            
    else:
        send_text_msg(active_peer, user_input)
        render_chat_ui()

def execute_main_loop():
    global active_peer, session_id, current_ui
    load_config()
    
    while True:
        if dbg_ck(): secure_exit()
            
        current_ui = "main"
        clear_screen()
        print(f"{color_blue}{color_bold}--- e2e manager ---{color_reset}")
        print(f"Downloads: {download_dir}\n")
        print("1. Connect to Node")
        print("2. Connect in Full Anonymous Mode (fam)")
        print("3. Create own node")
        print("4. Exit")
        
        saved_node_str = f"{app_config.get('host')}:{app_config.get('port')}" if app_config.get("host") else ""
        if saved_node_str and not app_config.get("active") and not app_config.get("anon_mode"):
            print(f"\n{color_green}[*] Saved node: {saved_node_str}{color_reset}")
            
        menu_choice = input("\n> ").strip()
        
        if menu_choice in ["1", "2"]:
            is_anon = (menu_choice == "2")
            clear_screen()
            print(f"{color_red}{color_bold}--- SECURITY WARNING ---{color_reset}")
            print("Intermediate nodes route your E2E traffic. They can see:")
            print(" - Your IP address and the IP of your peer")
            print(" - Exact timestamps and sizes of all messages")
            print(f"{color_yellow}CRITICAL: Only connect to trusted nodes or deploy your own!{color_reset}\n")
            
            if is_anon:
                print(f"{color_magenta}[*] fam (experemental): Ephemeral identity, no logs, no saved IP.{color_reset}\n")
            
            if app_config.get("host") and not is_anon:
                print(f"Saved Node: {app_config['host']}:{app_config['port']}")
                if input("Use saved node? (y/n): ").strip().lower() != 'y':
                    app_config["host"] = input("Host: ").strip()
                    port_input = input("Port [7234]: ").strip()
                    app_config["port"] = int(port_input) if port_input else 7234
                    app_config["key"] = input("Access Key: ").strip()
            else:
                app_config["host"] = input("Host: ").strip()
                port_input = input("Port [7234]: ").strip()
                app_config["port"] = int(port_input) if port_input else 7234
                app_config["key"] = input("Access Key: ").strip()
                
            app_config["active"] = True
            app_config["anon_mode"] = is_anon
            if not is_anon:
                save_config()
            
            print(f"{color_yellow}Establishing secure socket...{color_reset}")
            timeout_counter = 10.0
            while timeout_counter > 0 and not session_id and app_config["active"]:
                time.sleep(0.5)
                timeout_counter -= 0.5
                
            if not session_id:
                print(f"{color_red}Connection failed.{color_reset}")
                ds_nd()
                time.sleep(2.0)
                continue
                
            while app_config["active"]:
                if dbg_ck(): secure_exit()
                    
                if active_peer:
                    current_ui = "chat"
                    time.sleep(0.5)
                    continue
                    
                current_ui = "session"
                clear_screen()
                print(f"{color_blue}--- Menu ---{color_reset}")
                if is_anon:
                    print(f"Your ID: {color_magenta}{session_id} (is anonimous){color_reset}\n")
                else:
                    print(f"Your ID: {color_green}{session_id}{color_reset}\n")
                print("1. New Chat (Connect to Peer)")
                print("2. Active Chats")
                print("3. Check Encryption")
                print("4. Disconnect Node")
                
                session_choice = input("\n> ").strip()
                
                if session_choice == "1":
                    peer_id_input = input("Enter PeerID: ").strip().upper()
                    if len(peer_id_input) in [6, 16]:
                        tunnel_to_peer(peer_id_input)
                        active_peer = peer_id_input
                        current_ui = "chat"
                        render_chat_ui()
                        while active_peer and app_config["active"]:
                            handle_chat_input()
                                
                elif session_choice == "2":
                    while True:
                        current_ui = "session"
                        clear_screen()
                        print(f"{color_blue}--- Chats ---{color_reset}")
                        sessions_keys = list(chat_sessions.keys())
                        
                        if not sessions_keys:
                            print("No active chats.")
                            
                        for index, peer_id in enumerate(sessions_keys):
                            peer_status = "Secured" if chat_sessions[peer_id]["status"] == "secured" else "Connecting"
                            print(f"{index}. {peer_id} [{peer_status}]")
                            
                        selection = input("\nEnter number to open chat, or 'b' to go back: ").strip()
                        if selection.lower() == 'b':
                            break
                            
                        if selection.isdigit() and int(selection) < len(sessions_keys):
                            active_peer = sessions_keys[int(selection)]
                            current_ui = "chat"
                            render_chat_ui()
                            while active_peer and app_config["active"]:
                                handle_chat_input()
                                    
                elif session_choice == "3":
                    while True:
                        clear_screen()
                        print(f"{color_blue}--- Verify Encryption ---{color_reset}")
                        secured_chats = [peer_id for peer_id, session_data in chat_sessions.items() if session_data["status"] == "secured"]
                        
                        if not secured_chats:
                            print("No secured chats available.")
                            input("\nPress Enter to return...")
                            break
                            
                        for index, peer_id in enumerate(secured_chats):
                            print(f"{index}. {peer_id}")
                            
                        selection = input("\nSelect chat to verify, or 'b' to go back: ").strip()
                        if selection.lower() == 'b':
                            break
                            
                        if selection.isdigit() and int(selection) < len(secured_chats):
                            chosen_peer = secured_chats[int(selection)]
                            clear_screen()
                            print(f"{color_blue}--- Verify Encryption: {chosen_peer} ---{color_reset}\n")
                            print(f"       {gt_wd(chat_sessions[chosen_peer]['key'])}\n")
                            print("Both peers must see the exact same words and colors in the exact same order.")
                            print(f"{color_red}WARNING: Auto-checks (/check_enc) can be faked by a MITM.{color_reset}")
                            print("The ONLY 100% secure way is to manually compare these words via voice or in person!\n")
                            input("Press Enter to return...")
                            
                elif session_choice == "4":
                    ds_nd()
                    
        elif menu_choice == "3":
            create_own_node()
        elif menu_choice == "4":
            ds_nd()
            sys.exit(0)

def start_async_thread(loop_instance):
    asyncio.set_event_loop(loop_instance)
    loop_instance.create_task(listen_socket_loop())
    loop_instance.run_forever()

if __name__ == "__main__":
    event_loop = asyncio.new_event_loop()
    threading.Thread(target=start_async_thread, args=(event_loop,), daemon=True).start()
    execute_main_loop()
