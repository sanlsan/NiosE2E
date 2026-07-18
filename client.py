import os
import sys
import json
import time
import base64
import asyncio
import threading
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
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
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hkdf_derive(salt_bytes, material_bytes, info_bytes):
    return HKDF(SHA256(), 32, salt_bytes, info_bytes).derive(material_bytes)

def encrypt_aead(encryption_key, data_bytes):
    aesgcm = AESGCM(encryption_key)
    initialization_vector = os.urandom(12)
    return initialization_vector + aesgcm.encrypt(initialization_vector, data_bytes, None)

def decrypt_aead(encryption_key, cipher_payload):
    try:
        return AESGCM(encryption_key).decrypt(cipher_payload[:12], cipher_payload[12:], None)
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

async def handle_connection(reader, writer, static_key):
    session = ServerNodeSession(reader, writer, static_key)
    try:
        await session.handshake()
    except:
        return writer.close()
    
    session_id = secrets.token_hex(8).upper()
    clients_dict[session_id] = session
    print(f"[+] Client connected: {session_id}")
    
    try:
        await session.send_packet(json.dumps({"type": "system", "text": f"Session ID:{session_id}"}).encode())
        while True:
            received_data = await session.receive_packet()
            data_json = json.loads(received_data.decode())
            if data_json.get("action") == "send":
                target_peer = data_json.get("to")
                message_text = data_json.get("text")
                if target_peer in clients_dict:
                    await clients_dict[target_peer].send_packet(json.dumps({"type": "message", "from": session_id, "text": message_text}).encode())
    except:
        pass
    finally:
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
    print(f"PORT: 7234\\\\nACCESS KEY: {public_key_b64}\\\\n")
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(run_server())"""

server_b64 = base64.b64encode(server_source.encode()).decode()

def hkdf_derive(salt_bytes, material_bytes, info_bytes):
    return HKDF(SHA256(), 32, salt_bytes, info_bytes).derive(material_bytes)

def encrypt_aead(encryption_key, data_bytes):
    aesgcm = AESGCM(encryption_key)
    initialization_vector = os.urandom(12)
    return initialization_vector + aesgcm.encrypt(initialization_vector, data_bytes, None)

def decrypt_aead(encryption_key, cipher_payload):
    try:
        return AESGCM(encryption_key).decrypt(cipher_payload[:12], cipher_payload[12:], None)
    except:
        return None

def gt_wd(k_byt):
    if not k_byt:
        return ""
    dg_by = hashlib.sha256(k_byt).digest()
    w_lst = [
        "sigma", "chad", "giga", "rizz", "gyatt", "mewing", "skibidi", "ohio", "cringe", "based",
        "cope", "seethe", "mald", "yeet", "bruh", "pog", "poggers", "sus", "amogus", "stonks",
        "fomo", "hodl", "doge", "pepe", "wojak", "troll", "noob", "pwned", "rekt", "oof",
        "skillissue", "gitgud", "chungus", "harambe", "shrek", "sponge", "squidward", "fr", "nocap", "mid",
        "valid", "sheesh", "bussin", "glazing", "cook", "boomer", "zoomer", "doomer", "coomer", "heisenberg",
        "walter", "saul", "kek", "lol", "lmao", "rofl", "kappa", "pepega", "monkas", "lurk",
        "ratio", "canceled", "simp", "incel", "femcel", "goofy", "augh", "npc", "gigachad", "grindset",
        "alpha", "beta", "omega", "rizzler", "woke", "redpill", "bluepill", "blackpill", "doggo", "unhinged",
        "delulu", "solulu", "pookie", "bestie", "slay", "ate", "banger", "boujee", "skrt", "cap",
        "fam", "lit", "fire", "gucci", "salty", "shook", "tea", "shade", "flex", "clout"
    ]
    el_ms = []
    for idx in range(4):
        w_idx = dg_by[idx * 2] % 50
        c_idx = dg_by[idx * 2 + 1] % len(cl_ls)
        word = w_lst[w_idx]
        colr = cl_ls[c_idx]
        el_ms.append(f"{colr}{word}{color_reset}")
    return " | ".join(el_ms)

def enc_r(sess, t_yp, cont):
    tx_k = sess["tx_k"]
    seq = sess["tx"] + 1
    tx_k = hkdf_derive(None, tx_k, b"Ratchet")
    sess["tx_k"] = tx_k
    sess["tx"] = seq
    sess["key"] = hkdf_derive(None, min(tx_k, sess["rx_k"]) + max(tx_k, sess["rx_k"]), b"Visual")
    meta = {"t": t_yp, "s": seq}
    if t_yp == "file":
        meta["n"] = cont[0]
        meta["d"] = cont[1]
    else:
        meta["c"] = cont
    enc_d = encrypt_aead(tx_k, json.dumps(meta).encode())
    return enc_d, seq

def dec_r(sess, ciph, seq):
    rx_k = sess["rx_k"]
    rx_s = sess["rx"]
    if seq <= rx_s:
        if seq in sess["sk_ks"]:
            skipped_k = sess["sk_ks"].pop(seq)
            plain = decrypt_aead(skipped_k, ciph)
            return plain
        return None
    diff = seq - rx_s
    if diff > 100:
        raise ConnectionError("Ratchet step limit exceeded")
    for step in range(1, diff):
        skipped_seq = rx_s + step
        skipped_rx_k = hkdf_derive(None, rx_k, b"Ratchet")
        sess["sk_ks"][skipped_seq] = skipped_rx_k
        if len(sess["sk_ks"]) > 100:
            oldest = min(sess["sk_ks"].keys())
            sess["sk_ks"].pop(oldest)
        rx_k = skipped_rx_k
    rx_k = hkdf_derive(None, rx_k, b"Ratchet")
    plain = decrypt_aead(rx_k, ciph)
    if plain is not None:
        sess["prev_key"] = sess["key"]
        sess["rx_k"] = rx_k
        sess["rx"] = seq
        sess["key"] = hkdf_derive(None, min(sess["tx_k"], rx_k) + max(sess["tx_k"], rx_k), b"Visual")
    return plain

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
app_config = {"host": None, "port": None, "key": None, "active": False}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_config():
    global app_config
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as config_file:
                app_config = json.load(config_file)
        except:
            pass

def save_config():
    with open(config_path, "w") as config_file:
        json.dump(app_config, config_file)

def ds_nd():
    global node_socket, session_id
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

def render_chat_ui():
    if not active_peer:
        return
        
    clear_screen()
    wds_s = gt_wd(chat_sessions[active_peer]["key"]) if active_peer in chat_sessions and chat_sessions[active_peer]["status"] == "secured" else ""
    
    print(f"{color_blue}{color_bold}--- CHAT: {active_peer} ---{color_reset}")
    if wds_s:
        print(f" Key: {wds_s}\n")
        print(f"{color_yellow}Key changes with per message{color_reset}\n")
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
        if not app_config.get("active"):
            if node_socket:
                try:
                    node_socket.writer.close()
                except:
                    pass
                node_socket = None
            await asyncio.sleep(0.5)
            continue
            
        try:
            reader, writer = await asyncio.open_connection(app_config["host"], app_config["port"])
            decoded_key = base64.b64decode(app_config["key"])
            socket_session = ClientSocket(reader, writer, decoded_key)
            await socket_session.handshake()
            node_socket = socket_session
            
            while app_config.get("active"):
                packet_bytes = await node_socket.receive_packet()
                if not packet_bytes:
                    break
                    
                payload_json = json.loads(packet_bytes.decode())
                message_type = payload_json.get("type")
                
                if message_type == "system":
                    system_text = payload_json.get("text", "")
                    if "ID" in system_text:
                        session_id = system_text.split(":")[-1].strip()
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
                        
                        shared_secret = my_private_key.exchange(peer_public_key)
                        session_e2e_key = hkdf_derive(None, shared_secret, b"NiosE2E")
                        
                        tx_k = hkdf_derive(None, session_e2e_key, b"RespToInit")
                        rx_k = hkdf_derive(None, session_e2e_key, b"InitToResp")
                        
                        chat_sessions[sender_id] = {
                            "status": "secured",
                            "priv": None,
                            "tx_k": tx_k,
                            "rx_k": rx_k,
                            "tx": 0,
                            "rx": 0,
                            "key": hkdf_derive(None, min(tx_k, rx_k) + max(tx_k, rx_k), b"Visual"),
                            "prev_key": None,
                            "sk_ks": {}
                        }
                        
                        response_payload = json.dumps({"action": "send", "to": sender_id, "text": f"RESP:{my_public_b64}"})
                        await node_socket.send_packet(response_payload.encode())
                        
                        wds_s = gt_wd(chat_sessions[sender_id]["key"])
                        
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
                            
                            shared_secret = my_private_key.exchange(peer_public_key)
                            session_e2e_key = hkdf_derive(None, shared_secret, b"NiosE2E")
                            
                            tx_k = hkdf_derive(None, session_e2e_key, b"InitToResp")
                            rx_k = hkdf_derive(None, session_e2e_key, b"RespToInit")
                            
                            chat_sessions[sender_id]["tx_k"] = tx_k
                            chat_sessions[sender_id]["rx_k"] = rx_k
                            chat_sessions[sender_id]["key"] = hkdf_derive(None, min(tx_k, rx_k) + max(tx_k, rx_k), b"Visual")
                            chat_sessions[sender_id]["prev_key"] = None
                            chat_sessions[sender_id]["sk_ks"] = {}
                            chat_sessions[sender_id]["priv"] = None
                            chat_sessions[sender_id]["status"] = "secured"
                            chat_sessions[sender_id]["tx"] = 0
                            chat_sessions[sender_id]["rx"] = 0
                            
                            wds_s = gt_wd(chat_sessions[sender_id]["key"])
                            
                            if active_peer == sender_id and current_ui == "chat":
                                render_chat_ui()
                            elif current_ui != "main":
                                sys.stdout.write(f"\r\033[K{color_green}[+] Secure Chat established with {sender_id}{color_reset}\n> ")
                                sys.stdout.flush()
                                
                    elif message_text.startswith("MSG:"):
                        parts = message_text.split(":")
                        if len(parts) == 4 and sender_id in chat_sessions and chat_sessions[sender_id]["status"] == "secured":
                            cipher_payload = base64.b64decode(parts[1]) + base64.b64decode(parts[2])
                            seq = int(parts[3])
                            
                            decrypted_message = dec_r(chat_sessions[sender_id], cipher_payload, seq)
                            
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
                                    alert_text = "[+] Auto-check OK! Compare words manually." if command_ctx == "OK" else "[!] DANGER! Encryption mismatch! MITM possible!"
                                    alert_color = color_green if command_ctx == "OK" else color_red
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
                                target_path = os.path.join(download_dir, os.path.basename(metadata["n"]))
                                with open(target_path, "wb") as file_handler:
                                    file_handler.write(file_bytes)
                                content_str = f"{os.path.basename(metadata['n'])} (Saved to downloads)"
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
        
    enc_b, seq = enc_r(chat_sessions[peer_id], "cmd", cmd_text)
    nonce_base64 = base64.b64encode(enc_b[:12]).decode()
    cipher_base64 = base64.b64encode(enc_b[12:]).decode()
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"MSG:{nonce_base64}:{cipher_base64}:{seq}"}).encode()
    asyncio.run_coroutine_threadsafe(node_socket.send_packet(payload), event_loop)

def send_text_msg(peer_id, text_content):
    if peer_id not in chat_sessions or chat_sessions[peer_id]["status"] != "secured" or not node_socket:
        return
        
    enc_b, seq = enc_r(chat_sessions[peer_id], "txt", text_content)
    nonce_base64 = base64.b64encode(enc_b[:12]).decode()
    cipher_base64 = base64.b64encode(enc_b[12:]).decode()
    
    add_history_message(peer_id, session_id, text_content, False)
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"MSG:{nonce_base64}:{cipher_base64}:{seq}"}).encode()
    asyncio.run_coroutine_threadsafe(node_socket.send_packet(payload), event_loop)

def send_file_attachment(peer_id, file_path):
    if peer_id not in chat_sessions or chat_sessions[peer_id]["status"] != "secured" or not node_socket or not os.path.exists(file_path):
        return
        
    file_name = os.path.basename(file_path)
    with open(file_path, "rb") as file_handler:
        file_b64 = base64.b64encode(file_handler.read()).decode()
        
    enc_b, seq = enc_r(chat_sessions[peer_id], "file", (file_name, f"b64,{file_b64}"))
    nonce_base64 = base64.b64encode(enc_b[:12]).decode()
    cipher_base64 = base64.b64encode(enc_b[12:]).decode()
    
    add_history_message(peer_id, session_id, file_name, True)
    
    payload = json.dumps({"action": "send", "to": peer_id, "text": f"MSG:{nonce_base64}:{cipher_base64}:{seq}"}).encode()
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
sudo apt-get update && sudo apt-get install -y python3-pip
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
        current_ui = "main"
        clear_screen()
        print(f"{color_blue}{color_bold}--- e2e manager ---{color_reset}")
        print(f"Downloads: {download_dir}\n")
        print("1. Connect to Node")
        print("2. Create own node")
        print("3. Exit")
        
        if app_config.get("active"):
            print(f"\n{color_green}[*] You can connect at ur saved node: {app_config['host']}:{app_config['port']}{color_reset}")
            
        menu_choice = input("\n> ").strip()
        
        if menu_choice == "1":
            clear_screen()
            print(f"{color_red}{color_bold}--- SECURITY WARNING ---{color_reset}")
            print("Intermediate nodes route your E2E traffic. They can see:")
            print(" - Your IP address and the IP of your peer")
            print(" - Exact timestamps and sizes of all messages")
            print(f"{color_yellow}CRITICAL: Only connect to trusted nodes or deploy your own!{color_reset}\n")
            
            if app_config.get("host"):
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
                if active_peer:
                    current_ui = "chat"
                    time.sleep(0.5)
                    continue
                    
                current_ui = "session"
                clear_screen()
                print(f"{color_blue}--- Menu ---{color_reset}")
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
                            print("If they differ, your connection is compromised (MITM).\n")
                            input("Press Enter to return...")
                            
                elif session_choice == "4":
                    ds_nd()
                    
        elif menu_choice == "2":
            create_own_node()
        elif menu_choice == "3":
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
