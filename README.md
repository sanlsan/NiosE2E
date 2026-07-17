# NiosE2E: Getting Started Guide

Welcome to **NiosE2E**, a secure, decentralized, encrypted messenger where you can easily run and control your own node. Follow the simple steps below to get connected or deploy your private gateway.

---

### Step 1: Download the Client
To begin, download the client file appropriate for your system:
* **`client.py`** *(for Python users)*
* **`client.exe`** *(for Windows users)*

---

### Step 2: Run the Application
Launch the downloaded client on your system to open the interface.

---

### Step 3: Connect to a Node
To start chatting, enter the node's connection details. You can connect using the official public node:

| Parameter | Value |
| :--- | :--- |
| **IP Address** | `38.87.116.2` |
| **Port** | `7234` *(Default port)* |
| **Access Key** | `F1yV6Fred3uJtRoNSejek/EPr+QYD/9uF0ngexR+Izs=` |

#### 💬 How to Start Messaging:
1. **Copy Your ID:** Once connected, copy your unique ID from the interface.
2. **Share with Friends:** Send your ID to your friend.
3. **Wait for Connection:** Once they connect, you can start messaging securely.

> **Security Check (MITM Protection):**
> Look at the **E2E Secure Key** on your screen. It consists of four colored circles (`●●●●`).
> * **If the colors match** exactly on your screen and your friend's screen: The connection is secure, and no one is listening.
> * **If the colors are different:** Someone might be attempting to intercept your chat (Man-in-the-Middle attack). **Disconnect immediately.**

---

### Step 4: Host Your Own Private Node
If you prefer not to use public nodes, you can host your own gateway with full control:

1. In the main menu, select **Option 2**.
2. The client will instantly generate two deployment scripts in your folder:
   * `deploy_win.bat` *(for Windows)*
   * `deploy_lin.sh` *(for Linux)*
3. Transfer these files to your VPS or local PC.
4. Run the script to launch your private node.

---

*Enjoy secure, private conversations!*
