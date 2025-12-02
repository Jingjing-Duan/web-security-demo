#!/bin/bash
#
# SECURE Database Backup Script
# Creates timestamped backups of the SQLite database
#
# SECURITY FEATURES:
# - Timestamped backups for recovery points
# - Backup integrity verification
# - Secure file permissions
# - Retention policy (keeps last 7 days)
# - Encryption key EXCLUDED from backups
# - Backups encrypted with GPG (if available)
#

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../../data/secure_database.sqlite"
ENCRYPTION_KEY_FILE="$SCRIPT_DIR/../../data/.encryption_key"
BACKUP_DIR="$SCRIPT_DIR/../../backups"
RETENTION_DAYS=7
ENCRYPT_BACKUPS=true  # Set to false to disable backup encryption

# Create backup directory if not exists
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/backup_$TIMESTAMP.sqlite"

echo "=== Database Backup Script ==="
echo "Timestamp: $TIMESTAMP"
echo ""

# Check if source database exists
if [ ! -f "$DB_PATH" ]; then
    echo "ERROR: Database not found at $DB_PATH"
    exit 1
fi

echo "[1/4] Creating backup..."

# Use SQLite's backup command for consistency
if command -v sqlite3 &> /dev/null; then
    sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"
else
    # Fallback to file copy
    cp "$DB_PATH" "$BACKUP_FILE"
fi

if [ $? -eq 0 ]; then
    echo "      ✓ Backup created: $BACKUP_FILE"
else
    echo "      ✗ Backup failed!"
    exit 1
fi

echo "[2/4] Setting secure permissions..."
chmod 600 "$BACKUP_FILE"
echo "      ✓ Permissions set to 600"

echo "[3/4] Verifying backup integrity..."

# Verify backup can be opened
if command -v sqlite3 &> /dev/null; then
    INTEGRITY=$(sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" 2>&1)
    if [ "$INTEGRITY" = "ok" ]; then
        echo "      ✓ Integrity check passed"
    else
        echo "      ⚠ Integrity check: $INTEGRITY"
    fi
    
    # Show backup statistics
    USER_COUNT=$(sqlite3 "$BACKUP_FILE" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "?")
    COMMENT_COUNT=$(sqlite3 "$BACKUP_FILE" "SELECT COUNT(*) FROM comments;" 2>/dev/null || echo "?")
    echo "      Records: $USER_COUNT users, $COMMENT_COUNT comments"
fi

echo "[4/5] Encrypting backup..."

if [ "$ENCRYPT_BACKUPS" = true ]; then
    if command -v openssl &> /dev/null; then
        # Generate encryption passphrase from environment or create random
        if [ -n "$BACKUP_PASSPHRASE" ]; then
            PASSPHRASE="$BACKUP_PASSPHRASE"
        else
            PASSPHRASE=$(openssl rand -base64 32)
            echo "      ⚠ No BACKUP_PASSPHRASE env var set. Random passphrase generated:"
            echo "      Passphrase: $PASSPHRASE"
            echo "      (Store this securely to restore backup!)"
        fi

        # Encrypt with AES-256-CBC
        openssl enc -aes-256-cbc -salt -pbkdf2 -in "$BACKUP_FILE" -out "${BACKUP_FILE}.enc" -k "$PASSPHRASE"

        if [ $? -eq 0 ]; then
            # Remove unencrypted backup
            rm "$BACKUP_FILE"
            BACKUP_FILE="${BACKUP_FILE}.enc"
            echo "      ✓ Backup encrypted with AES-256-CBC"
        else
            echo "      ✗ Encryption failed, keeping unencrypted backup"
        fi
    else
        echo "      ⚠ OpenSSL not found, skipping encryption"
    fi
else
    echo "      - Encryption disabled"
fi

echo "[5/5] Cleaning old backups (keeping last $RETENTION_DAYS days)..."
find "$BACKUP_DIR" -name "backup_*.sqlite*" -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null
BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/backup_*.sqlite* 2>/dev/null | wc -l)
echo "      ✓ $BACKUP_COUNT backup(s) retained"

echo ""
echo "=== Backup Complete ==="
echo "Backup file: $BACKUP_FILE"
echo "Size: $(du -h "$BACKUP_FILE" | cut -f1)"
echo ""
echo "⚠ SECURITY REMINDERS:"
echo "  1. Encryption key NOT included in backup: $ENCRYPTION_KEY_FILE"
echo "  2. Store encryption key separately (use ENCRYPTION_KEY env var in production)"
if [ "$ENCRYPT_BACKUPS" = true ] && [ -z "$BACKUP_PASSPHRASE" ]; then
    echo "  3. Save the backup passphrase shown above to restore this backup"
fi
echo ""
echo "To restore encrypted backup:"
echo "  openssl enc -aes-256-cbc -d -pbkdf2 -in $BACKUP_FILE -out restored.sqlite -k <passphrase>"
