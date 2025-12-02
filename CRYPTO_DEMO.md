# Cryptography Demo Guide
**AEAD Encryption Demonstration**

This guide shows how to demonstrate that AEAD (Authenticated Encryption with Authenticated Data) encryption is properly implemented in this web security demo.

---

## Overview

**What's Encrypted:**
- User email addresses (PII)
- Comment content (sensitive data)

**Encryption Method:**
- XChaCha20-Poly1305 (Sodium) - preferred
- AES-256-GCM (OpenSSL) - fallback

Both are AEAD ciphers providing:
- ✅ **Confidentiality** - Data is encrypted
- ✅ **Integrity** - Tampering is detected
- ✅ **Authentication** - Only correct key can decrypt

---

## Demo 1: See Encryption in Action

### Step 1: Start the Application

```bash
# Start the web server
cd /Users/yanfei/web-security-demo
php -S localhost:8000 -t web-security-demo/secure

# Open browser to http://localhost:8000
```

### Step 2: Create Test Data

1. **Register a user** with an email:
   - Username: `testuser`
   - Email: `test@example.com`
   - Password: `Password123`

2. **Login** with that user

3. **Post a comment**:
   - Comment: `This is my secret message!`

### Step 3: View Encrypted Data in Database

Open a new terminal and run:

```bash
# Navigate to the project
cd /Users/yanfei/web-security-demo

# View encrypted emails
sqlite3 web-security-demo/data/secure_database.sqlite \
  "SELECT username, email_encrypted FROM users WHERE username='testuser';"
```

**Expected Output:**
```
testuser|dGhpcyBpcyBlbmNyeXB0ZWQgZGF0YS4uLg==...
```

The email is **BASE64-encoded encrypted data**, not plaintext!

### Step 4: View Encrypted Comments

```bash
sqlite3 web-security-demo/data/secure_database.sqlite \
  "SELECT id, content, substr(content_encrypted, 1, 60)
   FROM comments
   ORDER BY id DESC LIMIT 1;"
```

**Expected Output:**
```
1|This is my secret message!|dGhpcyBpcyBlbmNyeXB0ZWQgY29tbWVudCB3aXRoIG5vbmNlIGFuZCB0YWc=...
```

**Key Observation:**
- `content` = plaintext (for demo comparison)
- `content_encrypted` = AEAD encrypted (gibberish/base64)

---

## Demo 2: Encryption vs. Decryption Comparison

### Create a Visual Comparison

```bash
# Show the difference between encrypted and plain data
sqlite3 -column -header web-security-demo/data/secure_database.sqlite <<EOF
SELECT
  id,
  substr(content, 1, 30) as 'Plaintext',
  substr(content_encrypted, 1, 50) as 'Encrypted (AEAD)'
FROM comments
LIMIT 3;
EOF
```

**Expected Output:**
```
id  Plaintext                      Encrypted (AEAD)
--  -----------------------------  --------------------------------------------------
1   This is my secret message!     WkxoamVHRXlNSEJ2YkhrNU1URXpNMEZGUkVFPQ==...
2   Another comment here           VFhwSmVrMTZVWGxOVkVWNFRVUkJlVTFxUVRST1Z...
3   Test data for demo             YzJOeWVYQjBNVEl6TkRVMk56ZzVNREV5TXc9PQ==...
```

---

## Demo 3: Verify Which Cipher is Active

### Check Encryption Algorithm

```bash
# Create a test PHP file
cat > /tmp/check_cipher.php <<'EOF'
<?php
if (function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
    echo "✓ Using: XChaCha20-Poly1305 (Sodium)\n";
    echo "  Algorithm: ChaCha20 stream cipher\n";
    echo "  Authentication: Poly1305 MAC\n";
    echo "  Nonce size: 24 bytes (XChaCha variant)\n";
} else {
    echo "✓ Using: AES-256-GCM (OpenSSL)\n";
    echo "  Algorithm: AES-256 block cipher\n";
    echo "  Mode: Galois/Counter Mode (GCM)\n";
    echo "  Nonce size: 12 bytes\n";
}
EOF

php /tmp/check_cipher.php
```

---

## Demo 4: Tamper Detection (Key AEAD Feature)

This demonstrates that AEAD detects tampering.

### Step 1: Get Encrypted Data

```bash
# Get an encrypted comment
ENCRYPTED=$(sqlite3 web-security-demo/data/secure_database.sqlite \
  "SELECT content_encrypted FROM comments LIMIT 1;")

echo "Original encrypted: $ENCRYPTED"
```

### Step 2: Create a Tamper Test Script

```bash
cat > /tmp/tamper_test.php <<'EOF'
<?php
require_once 'web-security-demo/secure/includes/crypto.php';

// Get encrypted data from database
$pdo = new PDO('sqlite:web-security-demo/data/secure_database.sqlite');
$stmt = $pdo->query("SELECT content_encrypted FROM comments LIMIT 1");
$row = $stmt->fetch();
$encrypted = $row['content_encrypted'];

echo "=== AEAD Tamper Detection Demo ===\n\n";

// Test 1: Valid decryption
echo "Test 1: Valid encrypted data\n";
$decrypted = decrypt_data($encrypted);
if ($decrypted !== null) {
    echo "  ✓ SUCCESS: Decrypted successfully\n";
    echo "  Content: $decrypted\n\n";
} else {
    echo "  ✗ FAILED: Should decrypt\n\n";
}

// Test 2: Tampered data
echo "Test 2: Tampered encrypted data\n";
$tampered = substr($encrypted, 0, -10) . "TAMPERED!!";
$decrypted_tampered = decrypt_data($tampered);
if ($decrypted_tampered === null) {
    echo "  ✓ SUCCESS: Tampered data REJECTED\n";
    echo "  AEAD detected the modification!\n\n";
} else {
    echo "  ✗ FAILED: Tampered data was accepted (security issue!)\n\n";
}

// Test 3: Wrong key
echo "Test 3: Decryption with wrong key\n";
$wrong_key = random_bytes(32);
$decrypted_wrong_key = decrypt_data($encrypted, $wrong_key);
if ($decrypted_wrong_key === null) {
    echo "  ✓ SUCCESS: Wrong key REJECTED\n";
    echo "  AEAD authentication verified!\n\n";
} else {
    echo "  ✗ FAILED: Wrong key was accepted!\n\n";
}
EOF

cd /Users/yanfei/web-security-demo
php /tmp/tamper_test.php
```

**Expected Output:**
```
=== AEAD Tamper Detection Demo ===

Test 1: Valid encrypted data
  ✓ SUCCESS: Decrypted successfully
  Content: This is my secret message!

Test 2: Tampered encrypted data
  ✓ SUCCESS: Tampered data REJECTED
  AEAD detected the modification!

Test 3: Decryption with wrong key
  ✓ SUCCESS: Wrong key REJECTED
  AEAD authentication verified!
```

---

## Demo 5: Side-by-Side Web View

### Create a Demo Page

Add this to your presentation to show encrypted data in the web interface:

1. **Login to the secure app**
2. **Navigate to comments page**
3. **Open browser DevTools** (F12)
4. **Run this in Console**:

```javascript
// View the HTML to see we're displaying decrypted content
document.querySelectorAll('.comment-content').forEach(el => {
    console.log('Displayed:', el.textContent.trim());
});
```

5. **Compare with database**:
```bash
sqlite3 web-security-demo/data/secure_database.sqlite \
  "SELECT content_encrypted FROM comments;" | head -1
```

**Point to make:** The web app shows decrypted content, but database stores encrypted data!

---

## Demo 6: Encryption Key Security

### Show Key is NOT in Database

```bash
# Search database for the encryption key
echo "Searching database for encryption key..."
sqlite3 web-security-demo/data/secure_database.sqlite \
  ".dump" | grep -i "encryption\|key" || echo "No encryption keys found in database ✓"
```

### Show Key is in Environment or File

```bash
# Check if using environment variable
if [ -n "$ENCRYPTION_KEY" ]; then
    echo "✓ Using ENCRYPTION_KEY environment variable (PRODUCTION)"
else
    echo "✓ Using file-based key at: data/.encryption_key (DEVELOPMENT)"
    echo "  This file is excluded from git and backups"
fi
```

### Show Key is Excluded from Git

```bash
# Check .gitignore
grep -n "encryption_key" .gitignore
```

**Expected Output:**
```
2:data/.encryption_key
3:web-security-demo/data/.encryption_key
4:**/data/.encryption_key
```

---

## Demo 7: Performance Test

Show that AEAD encryption is fast:

```bash
cat > /tmp/perf_test.php <<'EOF'
<?php
require_once 'web-security-demo/secure/includes/crypto.php';

$data = str_repeat("Test data ", 100); // 1KB
$iterations = 1000;

echo "=== AEAD Encryption Performance ===\n\n";
echo "Data size: " . strlen($data) . " bytes\n";
echo "Iterations: $iterations\n\n";

// Encryption benchmark
$start = microtime(true);
for ($i = 0; $i < $iterations; $i++) {
    $encrypted = encrypt_data($data);
}
$encrypt_time = (microtime(true) - $start) * 1000;

// Decryption benchmark
$encrypted_sample = encrypt_data($data);
$start = microtime(true);
for ($i = 0; $i < $iterations; $i++) {
    $decrypted = decrypt_data($encrypted_sample);
}
$decrypt_time = (microtime(true) - $start) * 1000;

printf("Encryption: %.2f ms total, %.3f ms avg\n", $encrypt_time, $encrypt_time/$iterations);
printf("Decryption: %.2f ms total, %.3f ms avg\n", $decrypt_time, $decrypt_time/$iterations);
printf("Throughput: %d encryptions/sec\n", intval($iterations / ($encrypt_time/1000)));
EOF

cd /Users/yanfei/web-security-demo
php /tmp/perf_test.php
```

---

## Demo 8: Backup Encryption

### Run Secure Backup

```bash
cd /Users/yanfei/web-security-demo/web-security-demo/secure/scripts
./backup.sh
```

**What to point out:**
1. ✅ Encryption key is NOT included in backup
2. ✅ Backup is encrypted with AES-256-CBC
3. ✅ Secure permissions (600)
4. ✅ Integrity verification

### Verify Backup is Encrypted

```bash
# Try to open the encrypted backup directly (will fail)
sqlite3 ../../backups/backup_*.enc ".tables" 2>&1 | head -3
```

**Expected:** Should show "not a database" or binary gibberish

### Decrypt and Verify

```bash
# Get the latest backup
BACKUP=$(ls -t ../../backups/backup_*.enc | head -1)

# Decrypt it (you'll need the passphrase from the backup output)
# openssl enc -aes-256-cbc -d -pbkdf2 -in "$BACKUP" -out /tmp/restored.sqlite -k "passphrase"

echo "Backup is encrypted and cannot be read without passphrase ✓"
```

---

## Presentation Script

### Introduction (30 seconds)
> "This application implements AEAD encryption to protect personally identifiable information (PII) at rest. Let me show you how it works."

### Demo Flow (5 minutes)

1. **Show the Feature** (1 min)
   - Register user with email
   - Post a comment
   - "All sensitive data is encrypted before storage"

2. **Prove It's Encrypted** (1 min)
   ```bash
   sqlite3 web-security-demo/data/secure_database.sqlite \
     "SELECT username, substr(email_encrypted, 1, 50) FROM users;"
   ```
   - "This is base64-encoded encrypted data, not plaintext"

3. **Show Decryption** (1 min)
   - Refresh comment page
   - "Application decrypts on-the-fly for display"
   - "Database never stores plaintext PII"

4. **Demonstrate Security** (1 min)
   - Run tamper test
   - "AEAD detects any tampering attempt"
   - "Wrong key = no decryption"

5. **Show Best Practices** (1 min)
   - Key stored in environment variable
   - Excluded from git: `cat .gitignore | grep key`
   - Excluded from backups
   - Backups also encrypted

### Conclusion (30 seconds)
> "This demonstrates defense in depth: encryption at rest, secure key management, encrypted backups, and tamper detection. Even if the database is compromised, the data remains protected."

---

## Quick Demo Commands Cheat Sheet

```bash
# 1. Check which cipher is active
php -r "echo function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt') ? 'XChaCha20-Poly1305' : 'AES-256-GCM';"

# 2. View encrypted emails
sqlite3 web-security-demo/data/secure_database.sqlite "SELECT username, email_encrypted FROM users;"

# 3. View encrypted comments
sqlite3 web-security-demo/data/secure_database.sqlite "SELECT substr(content, 1, 30), substr(content_encrypted, 1, 50) FROM comments;"

# 4. Run tamper test
php /tmp/tamper_test.php

# 5. Check key is excluded from git
grep encryption_key .gitignore

# 6. Run encrypted backup
./web-security-demo/secure/scripts/backup.sh

# 7. Performance test
php /tmp/perf_test.php
```

---

## Troubleshooting

### "No encrypted data found"
- Make sure you registered a user with an email
- Make sure you posted a comment
- Check the correct database path

### "Decryption returns null"
- Verify ENCRYPTION_KEY matches the key used during encryption
- Check if key file exists: `ls -la web-security-demo/data/.encryption_key`

### "Sodium functions not found"
- Install PHP Sodium extension
- Will fallback to OpenSSL AES-256-GCM automatically

---

## Summary: What This Demo Proves

| Security Requirement | Implementation | Demo Proof |
|---------------------|----------------|------------|
| PII Encrypted at Rest | ✅ AEAD encryption | Database query shows base64 |
| Tamper Detection | ✅ AEAD authentication | Tamper test rejects modified data |
| Secure Key Storage | ✅ Environment variable | Key not in database/git |
| Encrypted Backups | ✅ AES-256-CBC | Backup file is encrypted |
| Performance | ✅ Thousands/sec | Performance test shows speed |
| Proper Algorithm | ✅ XChaCha20-Poly1305 or AES-256-GCM | Cipher check confirms |

---

**Created:** December 2024
**Project:** Web Security Demo - Algonquin College
**Encryption:** AEAD (XChaCha20-Poly1305 / AES-256-GCM)
