# Security Configuration Guide

This document explains the security features implemented in this web security demo and how to configure them for production use.

## 1. AEAD Encryption for PII

### What's Encrypted
- User email addresses (stored in `users.email_encrypted`)
- Comment content (stored in `comments.content_encrypted`)
- Uses XChaCha20-Poly1305 (Sodium) or AES-256-GCM (OpenSSL fallback)

### Configuration

#### Development/Demo Mode
The application generates and stores an encryption key in `data/.encryption_key`.

**⚠️ This file is:**
- Excluded from git (see `.gitignore`)
- Excluded from backups
- Should NEVER be committed to version control

#### Production Mode
Set the encryption key via environment variable:

```bash
# Generate a secure key
export ENCRYPTION_KEY=$(openssl rand -base64 32)

# Or use your secret manager (AWS, GCP, Azure, etc.)
export ENCRYPTION_KEY="your-base64-encoded-32-byte-key"
```

**Production Checklist:**
- ✅ Set `ENCRYPTION_KEY` environment variable
- ✅ Remove `data/.encryption_key` file from production servers
- ✅ Store key in secret manager (AWS Secrets Manager, HashiCorp Vault, etc.)
- ✅ Rotate key periodically (requires data re-encryption)

### Files Modified
- `secure/includes/crypto.php` - Encryption functions with env variable support
- `secure/comments.php` - Encrypts comment content
- `secure/register.php` - Encrypts email addresses

---

## 2. Backup Security

### Backup Script Features
Located at: `secure/scripts/backup.sh`

**Security Features:**
- ✅ Encryption key EXCLUDED from backups
- ✅ Backups encrypted with AES-256-CBC
- ✅ Secure file permissions (600)
- ✅ Integrity verification
- ✅ Retention policy (7 days default)

### Usage

#### Basic Backup
```bash
cd secure/scripts
./backup.sh
```

#### Production Backup (with passphrase)
```bash
export BACKUP_PASSPHRASE="your-secure-passphrase"
./backup.sh
```

**⚠️ Important:**
- Store backup passphrase securely (separate from encryption key!)
- Without the passphrase, encrypted backups cannot be restored
- Encryption key is NOT included in backups (must be stored separately)

### Restoring Encrypted Backup
```bash
# Decrypt the backup
openssl enc -aes-256-cbc -d -pbkdf2 \
  -in backups/backup_TIMESTAMP.sqlite.enc \
  -out restored.sqlite \
  -k "your-backup-passphrase"

# Restore to database
cp restored.sqlite data/secure_database.sqlite

# IMPORTANT: Also restore the encryption key!
# Without it, encrypted data (emails, comments) cannot be decrypted
export ENCRYPTION_KEY="your-original-key"
```

### Disable Backup Encryption (not recommended)
Edit `secure/scripts/backup.sh`:
```bash
ENCRYPT_BACKUPS=false
```

---

## 3. HTTPS Configuration

### Session Cookie Secure Flag
**Auto-detection:** The session cookie `secure` flag is automatically set based on HTTPS detection.

Detects HTTPS from:
- `$_SERVER['HTTPS']`
- `$_SERVER['HTTP_X_FORWARDED_PROTO']` (load balancers)
- `$_SERVER['HTTP_X_FORWARDED_SSL']`
- `$_SERVER['SERVER_PORT']` (443)

### Force HTTPS Redirect
**Enable HTTP→HTTPS redirect:**

```bash
export FORCE_HTTPS=true
```

Or in your web server configuration (recommended):

#### Apache (.htaccess)
```apache
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
```

#### Nginx
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### Files Modified
- `secure/includes/auth.php` - Added `is_https()` and `force_https()` functions

---

## 4. Production Environment Variables

### Required for Production

```bash
# Encryption key (32 bytes, base64-encoded)
export ENCRYPTION_KEY="<base64-key>"

# Backup encryption passphrase
export BACKUP_PASSPHRASE="<secure-passphrase>"

# Force HTTPS redirects (optional, recommended)
export FORCE_HTTPS=true
```

### Generate Secure Values

```bash
# Generate encryption key
openssl rand -base64 32

# Generate backup passphrase
openssl rand -base64 32

# Or use a password manager to generate passphrases
```

---

## 5. Security Checklist for Production

### Before Deployment
- [ ] Set `ENCRYPTION_KEY` environment variable
- [ ] Set `BACKUP_PASSPHRASE` environment variable
- [ ] Enable `FORCE_HTTPS=true`
- [ ] Remove `data/.encryption_key` from production
- [ ] Verify `.gitignore` excludes sensitive files
- [ ] Test backup and restore process
- [ ] Store keys in secret manager (AWS, GCP, Azure, Vault)

### After Deployment
- [ ] Verify HTTPS is working
- [ ] Test session cookies have `secure` flag
- [ ] Verify encrypted data in database (emails, comments)
- [ ] Test backup encryption
- [ ] Setup automated backup schedule
- [ ] Document key rotation procedure

### Ongoing Maintenance
- [ ] Rotate encryption keys annually
- [ ] Test backup restoration quarterly
- [ ] Review backup retention policy
- [ ] Monitor for encryption key exposure
- [ ] Update dependencies regularly

---

## 6. Database Verification

### Check Encrypted Data

```bash
# View encrypted emails
sqlite3 data/secure_database.sqlite \
  "SELECT username, substr(email_encrypted, 1, 50) FROM users;"

# View encrypted comments
sqlite3 data/secure_database.sqlite \
  "SELECT id, substr(content_encrypted, 1, 50) FROM comments;"
```

You should see base64-encoded strings, not plaintext.

### Demo Encryption in Action

1. Register a new user with an email
2. Post a comment
3. View the database - data should be encrypted
4. View in the web app - data should be decrypted and readable

---

## 7. Key Rotation Procedure

### Encryption Key Rotation

```bash
# 1. Generate new key
NEW_KEY=$(openssl rand -base64 32)

# 2. Run re-encryption script (create this for your needs)
php secure/scripts/rotate_encryption_key.php --old-key="$OLD_KEY" --new-key="$NEW_KEY"

# 3. Update environment variable
export ENCRYPTION_KEY="$NEW_KEY"

# 4. Restart application
```

**Note:** Key rotation script not included in this demo. For production, implement a script that:
1. Decrypts all data with old key
2. Re-encrypts with new key
3. Updates database atomically

---

## 8. Troubleshooting

### "Encrypted content" showing in comments
- Check `ENCRYPTION_KEY` is set correctly
- Verify key matches the one used during encryption
- Check logs for decryption errors

### Backup restore fails
- Verify backup passphrase is correct
- Check OpenSSL is installed
- Ensure backup file is not corrupted

### HTTPS redirect loop
- Check load balancer forwards `X-Forwarded-Proto` header
- Verify `is_https()` detection logic
- Disable `FORCE_HTTPS` if testing locally

---

## 9. References

### AEAD Encryption
- [XChaCha20-Poly1305 (Sodium)](https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php)
- [AES-256-GCM (OpenSSL)](https://www.php.net/manual/en/function.openssl-encrypt.php)

### Key Management
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [GCP Secret Manager](https://cloud.google.com/secret-manager)

### Backup Encryption
- [OpenSSL AES-256-CBC](https://www.openssl.org/docs/man1.1.1/man1/enc.html)

---

## Security Features Summary

| Feature | Implementation | Status |
|---------|----------------|--------|
| PII Encryption | AEAD (XChaCha20-Poly1305/AES-256-GCM) | ✅ |
| Encryption Key Storage | Environment variable | ✅ |
| Backup Exclusions | .gitignore + backup script | ✅ |
| Backup Encryption | AES-256-CBC with OpenSSL | ✅ |
| Session Cookie Secure | Auto-detect HTTPS | ✅ |
| HTTPS Redirect | Environment variable controlled | ✅ |

---

**Last Updated:** 2024
**Project:** Web Security Demo - Algonquin College
