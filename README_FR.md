
# MYA Ransomware - README

## ATTENTION

Il s'agit d'un projet scolaire. Il est strictement interdit d'utiliser ce code à des fins malveillantes. L'utilisation autorisée est uniquement à des fins pédagogiques.
De plus, il est possible que le code ne fonctionne pas parfaitement, et nous ne sommes pas responsables en cas de perte ou de destruction de données liée à son utilisation.

## Vue d'ensemble
La solution MYA ransomware se compose de deux fichiers séparés en C : `server.c` et `mya.c`. Le ransomware chiffre les fichiers et envoie la clé de chiffrement à un serveur distant pour un stockage sécurisé. Il prend également en charge le déchiffrement en fournissant la clé et le vecteur d'initialisation (IV) corrects.

## Composants
- **server.c** : Un programme serveur qui attend les connexions TCP entrantes, reçoit la clé de chiffrement et l'IV, et les affiche.
- **mya.c** : Le programme ransomware qui chiffre/déchiffre les fichiers et communique avec le serveur.

## Instructions d'utilisation

### 1. **Configurer le serveur**
   Le serveur est responsable de recevoir la clé de chiffrement et l'IV du ransomware et de les afficher.

#### Étapes :
1. **Compiler et lancer le serveur**
   - Définir l'adresse IP du serveur sur `192.168.1.1/24`. Assurez-vous que la machine est connectée au réseau avec l'IP statique correcte.
   - Compiler le code du serveur :
     ```bash
     gcc -o server server.c
     ```
   - Lancer le serveur :
     ```bash
     ./server
     ```

### 2. **Configurer le ransomware (MYA)**

#### **Mode de chiffrement :**
1. **Compiler et exécuter MYA en mode chiffrement**
   - Compiler le code du ransomware :
     ```bash
     gcc -o mya mya.c -lcrypto
     ```
   - Exécuter le ransomware en mode chiffrement sur un fichier ou un répertoire :
     ```bash
     ./mya e "chemin_vers_le_fichier_ou_répertoire"
     ```
   - Le programme effectuera :
     - La génération d'une clé de chiffrement et d'un IV aléatoires.
     - Le chiffrement des fichiers dans le chemin spécifié.
     - L'envoi de la clé et de l'IV au serveur.

#### **Mode de déchiffrement :**
1. **Lancer le mode déchiffrement**
   - Pour déchiffrer les fichiers, la clé et l'IV corrects sont nécessaires.
   - Exécuter le ransomware en mode déchiffrement avec la clé et l'IV fournis :
     ```bash
     ./mya d "chemin_vers_le_fichier_ou_répertoire_chiffré" "clé_de_chiffrement" "IV"
     ```

   **ATTENTION** : Lorsque vous passez la clé et l'IV pour le déchiffrement, **ne copiez-pas/coller pas** ces valeurs. Toute erreur de copie rendra le déchiffrement impossible.

### 3. **Gestion des fichiers**
   - **Chiffrement** : Lors du chiffrement, tous les fichiers du chemin spécifié sont chiffrés avec l'AES-256-CBC. La clé et l'IV sont envoyés en toute sécurité au serveur.
   - **Déchiffrement** : Pour déchiffrer les fichiers, la clé et l'IV utilisés lors du chiffrement doivent être fournis. Assurez-vous que la clé et l'IV utilisés pour le déchiffrement sont identiques à ceux utilisés pour le chiffrement.

### 4. **Réception de la clé par le serveur**
   - Le serveur écoute sur l'IP `192.168.1.1` et le port `6969`. Il reçoit la clé de chiffrement et l'IV, puis les affiche pour être utilisés lors du déchiffrement.

---

## Exemple d'utilisation

### **Chiffrement d'un répertoire**
1. **Lancer le serveur** :
   ```bash
   ./server
   ```
2. **Exécuter MYA en mode chiffrement** :
   ```bash
   ./mya e "/chemin/vers/répertoire"
   ```

   Le processus de chiffrement commencera, et la clé ainsi que l'IV seront envoyés au serveur.

### **Déchiffrement d'un fichier**
1. **Obtenir la clé et l'IV depuis le serveur**.
2. **Exécuter MYA en mode déchiffrement** :
   ```bash
   ./mya d "/chemin/vers/fichier_chiffré" "clé_de_chiffrement" "IV"
   ```

---

## Avertissement
- **Échec du déchiffrement** : Si la clé ou l'IV ne sont pas fournis correctement, le déchiffrement échouera. Assurez-vous que la clé et l'IV sont exactement les mêmes que ceux utilisés lors du chiffrement (ne les modifiez pas et ne copiez pas/collez pas).

---

## Licence
Ce projet est sous licence MIT. Consultez le fichier LICENSE pour plus de détails.
```
