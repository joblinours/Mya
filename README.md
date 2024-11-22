# MYA Ransomware - README

## WARNING:
This is a school project. It is strictly prohibited to use this code for any malicious purposes. The only permitted use is for educational purposes. 
Additionally, the code may not function perfectly, and we are not responsible for any data loss or destruction caused by its use.


## Overview
The MYA ransomware solution consists of two separate C files: `server.c` and `mya.c`. The ransomware encrypts files and sends the encryption key to a remote server for secure storage. It also supports decryption by providing the correct key and initialization vector (IV).

## Components
- **server.c**: A server program that listens for incoming TCP connections, receives the encryption key and IV, and prints them.
- **mya.c**: The ransomware program that encrypts/decrypts files and communicates with the server.

## Instructions for Use

### 1. **Configure the Server**
   The server is responsible for receiving the encryption key and IV from the ransomware and printing it.

#### Steps:
1. **Compile and Launch the Server**
   - Set the server's IP address to `192.168.1.1/24`. Ensure the machine is connected to the network with the correct static IP.
   - Compile the server code:
     ```bash
     gcc -o server server.c
     ```
   - Launch the server:
     ```bash
     ./server
     ```

### 2. **Configure the Ransomware (MYA)**

#### **Encryption Mode:**
1. **Compile and Run MYA in Encryption Mode**
   - Compile the ransomware code:
     ```bash
     gcc -o mya mya.c -lcrypto
     ```
   - Run the ransomware in encryption mode on a file or directory:
     ```bash
     ./mya e "path_to_file_or_directory"
     ```
   - The program will:
     - Generate a random encryption key and IV.
     - Encrypt the files in the specified path.
     - Send the key and IV to the server.

#### **Decryption Mode:**
1. **Start the Decryption Mode**
   - To decrypt the files, the correct key and IV are required.
   - Run the ransomware in decryption mode with the provided key and IV:
     ```bash
     ./mya d "path_to_encrypted_file_or_directory" "encryption_key" "IV"
     ```

   **WARNING**: When passing the key and IV for decryption, **do not copy/paste** them. Any error in copying the values will cause decryption to fail.

### 3. **File Handling**
   - **Encryption**: During encryption, all files in the specified path are encrypted with AES-256-CBC encryption. The key and IV are securely sent to the server.
   - **Decryption**: To decrypt the files, the correct key and IV must be provided. Ensure the key and IV used during decryption are the same as those used for encryption.

### 4. **Server Key Reception**
   - The server listens on IP `192.168.1.1` and port `6969`. It receives the encryption key and IV, then prints them for later use in decryption.

---

## Example Use Case

### **Encrypting a Directory**
1. **Run the Server**:
   ```bash
   ./server
   ```
2. **Run MYA in Encryption Mode**:
   ```bash
   ./mya e "/path/to/directory"
   ```

   The encryption process will begin, and the encryption key and IV will be sent to the server.

### **Decrypting a File**
1. **Obtain the Key and IV from the Server**.
2. **Run MYA in Decryption Mode**:
   ```bash
   ./mya d "/path/to/encrypted_file" "encryption_key" "IV"
   ```

---

## Warning
- **Decryption Failure**: If the key or IV is not correctly provided, decryption will fail. Make sure the key and IV are exactly as generated during encryption (do not alter or copy/paste).

---

## License
This project is licensed under the MIT License. See the LICENSE file for details.
