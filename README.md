# Secure Data Relay using ECC-based Proxy Re-Encryption

This project implements a secure data relay mechanism between Digital Twins using
Elliptic Curve Cryptography (ECC) and Proxy Re-Encryption (PRE), based on the proposed
protocol in the reference paper.

The system consists of:

- Trusted Authority (TA)
- Edge Server (Proxy)
- Multiple Digital Twins (DTs)

Each Digital Twin can act as both a sender and a receiver.

---

## 📦 Prerequisites

- Python 3.8+
- Linux / WSL (tested on Ubuntu via WSL)
- Virtual environment support

System packages (WSL/Linux):

```bash
sudo apt update
sudo apt install -y python3 python3-venv build-essential libgmp-dev
```

## 🔧 Setup Instructions

### 1. Clone the repository

```bash
git clone <your-repo-url>
```

### 2. Create and activate virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install fastecdsa python-dotenv
```

## ⚙️ Configuration

Digital Twin identities are configured using environment variables.

#### Example:

```bash
export DT_ID=DT_1
```

Supported Digital Twins:

- DT_1
- DT_2

Ports and identities are defined inside the code (DT_CONFIG).

## ▶️ Execution Order

    Important: Run components in the following order.

1. Digital Twin Instances

   Open two separate terminals.
   Terminal 1 (DT_1):

   ```bash
   export DT_ID=DT_1
   cd "POC Digital Twin"
   python poc_dt.py
   ```

   Terminal 2 (DT_2):

   ```bash
   export DT_ID=DT_2
   cd "POC Digital Twin"
   python poc_dt.py
   ```

2. Edge Server

```bash
cd "Edge Server"
python edge_server.py
```

3. Trusted Authority

```bash
cd "Trusted Authority"
python params_key_gen.py
```

Each Digital Twin:

- listens for incoming data in the background
- can send data interactively via the Edge Server

## 🔐 Notes

- ECC curve used: secp256k1
- Data is hashed and mapped to curve points (hash-to-point)
- Edge Server cannot decrypt data
- Replay protection is implemented using timestamps

## 📄 Assumptions

- The demo uses two Digital Twins for clarity.
- The design naturally scales to multiple Digital Twins by extending identity mappings.
- Secure channels for initial key distribution are assumed.
