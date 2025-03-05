# IoT Multi-Party Encryption – Hybrid RSA and ElGamal

This repository contains **research code** and a **graphical interface** that demonstrates a **collaborative multi-party encryption** system for IoT environments. The system combines **RSA** and **ElGamal** cryptographic techniques, with a “nested” or **stacked** encryption approach involving multiple IoT nodes (source, intermediates, and destination). The graphical user interface (GUI) simulates a small IoT network, encrypts a user-supplied message, and then performs the FILO (First-In-Last-Out) decryption.

---

## Table of Contents

1. [Architecture & Core Features](#architecture--core-features)  
2. [Getting Started](#getting-started)  
3. [Usage](#usage)  

---

## Architecture & Core Features

- **Destination Node**: Initiates the nested key structure.  
- **Intermediate Nodes**: Contribute their partial keys (RSA φ(n) and random offsets).  
- **Source Node**: Finalizes the key and encrypts the message.  
- **RSA Encryption**: The system calculates the global modulus by multiplying each node’s `n`. A nested key is built by adding every node’s φ(n) and random offset, culminating in a collaborative exponent.  
- **ElGamal Encryption (Hybrid Mode)**: Each node has an exponent `x_i` in a shared prime group `p_g` and a common generator `g`, forming a collaborative public key `y_total = Π(y_i)`.  

---

### Prerequisites

- **Python 3.7+**  
- **Tkinter** (usually included in most Python installations)  
- **gmpy2** for arbitrary-precision arithmetic:
  ```bash
  pip install gmpy2
  ```

### Installation

1. **Clone or download** this repository.  
2. Ensure you have the prerequisites installed.  

---

## Usage

1. **Run the application**:
   ```bash
   python iot_encryption_gui.py
   ```
2. **Select configuration**:
   - **IoT Nodes**: The number of intermediate nodes to insert between Source & Destination.  
   - **Key Size (bits)**: 64 (very small, for demonstration), 128, or 256.  
   - **Security Mode**: “Hybrid (RSA and ElGamal).”  
   - **Message**: Integer to encrypt.

3. **Initialize Network**:  
   - Click **“Initialize Network”** to start the entire multi-party encryption.  

4. **Observe Output**:  
   - The left panel depicts each device as an LED circle.  
   - The center lines show encryption links.  
   - The right panel logs initialization, key building, encryption, and final decryption.  

---
