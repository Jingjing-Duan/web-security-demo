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
#

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../../data/secure_database.sqlite"
BACKUP_DIR="$SCRIPT_DIR/../../backups"
RETENTION_DAYS=7

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

echo "[4/4] Cleaning old backups (keeping last $RETENTION_DAYS days)..."
find "$BACKUP_DIR" -name "backup_*.sqlite" -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null
BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/backup_*.sqlite 2>/dev/null | wc -l)
echo "      ✓ $BACKUP_COUNT backup(s) retained"

echo ""
echo "=== Backup Complete ==="
echo "Backup file: $BACKUP_FILE"
echo "Size: $(du -h "$BACKUP_FILE" | cut -f1)"
echo ""
echo "To restore: cp $BACKUP_FILE $DB_PATH"
