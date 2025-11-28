<?php
/**
 * Database Initialization Script
 * Creates both vulnerable and secure databases with sample data
 */

echo "=== Web Security Demo - Database Setup ===\n\n";

// Paths
$vulnerableDbPath = __DIR__ . '/../vulnerable/db/database.sqlite';
$secureDbPath = __DIR__ . '/../data/secure_database.sqlite';

// Ensure directories exist
@mkdir(dirname($vulnerableDbPath), 0755, true);
@mkdir(dirname($secureDbPath), 0755, true);

// Remove existing databases
@unlink($vulnerableDbPath);
@unlink($secureDbPath);

// ============================================
// VULNERABLE DATABASE SETUP
// ============================================
echo "[1/2] Setting up VULNERABLE database...\n";

try {
    $vulnDb = new SQLite3($vulnerableDbPath);
    
    // Create users table (plain text passwords - VULNERABLE!)
    $vulnDb->exec("
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    
    // Create comments table
    $vulnDb->exec("
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ");
    
    // Insert sample users with PLAIN TEXT passwords (VULNERABLE!)
    $vulnDb->exec("INSERT INTO users (username, password, email) VALUES ('admin', 'admin123', 'admin@example.com')");
    $vulnDb->exec("INSERT INTO users (username, password, email) VALUES ('user1', 'password1', 'user1@example.com')");
    $vulnDb->exec("INSERT INTO users (username, password, email) VALUES ('user2', 'password2', 'user2@example.com')");
    
    // Insert sample comments
    $vulnDb->exec("INSERT INTO comments (user_id, content) VALUES (1, 'Welcome to the comment section!')");
    $vulnDb->exec("INSERT INTO comments (user_id, content) VALUES (2, 'This is a test comment from user1.')");
    $vulnDb->exec("INSERT INTO comments (user_id, content) VALUES (3, 'Hello everyone!')");
    
    $vulnDb->close();
    echo "   ✓ Vulnerable database created at: $vulnerableDbPath\n";
    echo "   ⚠ WARNING: Passwords stored in PLAIN TEXT!\n\n";
    
} catch (Exception $e) {
    echo "   ✗ Error: " . $e->getMessage() . "\n";
    exit(1);
}

// ============================================
// SECURE DATABASE SETUP
// ============================================
echo "[2/2] Setting up SECURE database...\n";

try {
    $secureDb = new SQLite3($secureDbPath);
    
    // Create users table with hashed passwords
    $secureDb->exec("
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email_encrypted TEXT,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    
    // Create comments table with author tracking
    $secureDb->exec("
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            content_encrypted TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ");
    
    // Create audit log table
    $secureDb->exec("
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT NOT NULL,
            record_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            user_id INTEGER,
            old_value TEXT,
            new_value TEXT,
            ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    
    // Create sessions table for secure session management
    $secureDb->exec("
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT NOT NULL UNIQUE,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ");
    
    // Create trigger for audit logging on comments INSERT
    $secureDb->exec("
        CREATE TRIGGER audit_comments_insert
        AFTER INSERT ON comments
        BEGIN
            INSERT INTO audit_log (table_name, record_id, action, user_id, new_value)
            VALUES ('comments', NEW.id, 'INSERT', NEW.user_id, NEW.content);
        END
    ");
    
    // Create trigger for audit logging on comments UPDATE
    $secureDb->exec("
        CREATE TRIGGER audit_comments_update
        AFTER UPDATE ON comments
        BEGIN
            INSERT INTO audit_log (table_name, record_id, action, user_id, old_value, new_value)
            VALUES ('comments', NEW.id, 'UPDATE', NEW.user_id, OLD.content, NEW.content);
        END
    ");
    
    // Create trigger for audit logging on comments DELETE
    $secureDb->exec("
        CREATE TRIGGER audit_comments_delete
        AFTER DELETE ON comments
        BEGIN
            INSERT INTO audit_log (table_name, record_id, action, user_id, old_value)
            VALUES ('comments', OLD.id, 'DELETE', OLD.user_id, OLD.content);
        END
    ");
    
    // Insert sample users with HASHED passwords (SECURE!)
    // Using PASSWORD_DEFAULT which uses bcrypt (or argon2id if available)
    $adminHash = password_hash('admin123', PASSWORD_DEFAULT);
    $user1Hash = password_hash('password1', PASSWORD_DEFAULT);
    $user2Hash = password_hash('password2', PASSWORD_DEFAULT);
    
    $stmt = $secureDb->prepare("INSERT INTO users (username, password_hash, email_encrypted, role) VALUES (:username, :hash, :email, :role)");
    
    $stmt->bindValue(':username', 'admin', SQLITE3_TEXT);
    $stmt->bindValue(':hash', $adminHash, SQLITE3_TEXT);
    $stmt->bindValue(':email', 'admin@example.com', SQLITE3_TEXT); // Would be encrypted in real app
    $stmt->bindValue(':role', 'admin', SQLITE3_TEXT);
    $stmt->execute();
    
    $stmt->bindValue(':username', 'user1', SQLITE3_TEXT);
    $stmt->bindValue(':hash', $user1Hash, SQLITE3_TEXT);
    $stmt->bindValue(':email', 'user1@example.com', SQLITE3_TEXT);
    $stmt->bindValue(':role', 'user', SQLITE3_TEXT);
    $stmt->execute();
    
    $stmt->bindValue(':username', 'user2', SQLITE3_TEXT);
    $stmt->bindValue(':hash', $user2Hash, SQLITE3_TEXT);
    $stmt->bindValue(':email', 'user2@example.com', SQLITE3_TEXT);
    $stmt->bindValue(':role', 'user', SQLITE3_TEXT);
    $stmt->execute();
    
    // Insert sample comments
    $commentStmt = $secureDb->prepare("INSERT INTO comments (user_id, content) VALUES (:user_id, :content)");
    
    $commentStmt->bindValue(':user_id', 1, SQLITE3_INTEGER);
    $commentStmt->bindValue(':content', 'Welcome to the secure comment section!', SQLITE3_TEXT);
    $commentStmt->execute();
    
    $commentStmt->bindValue(':user_id', 2, SQLITE3_INTEGER);
    $commentStmt->bindValue(':content', 'This is a secure test comment from user1.', SQLITE3_TEXT);
    $commentStmt->execute();
    
    $commentStmt->bindValue(':user_id', 3, SQLITE3_INTEGER);
    $commentStmt->bindValue(':content', 'Hello everyone! This system is secure.', SQLITE3_TEXT);
    $commentStmt->execute();
    
    $secureDb->close();
    
    // Set restrictive permissions on secure database
    chmod($secureDbPath, 0600);
    
    echo "   ✓ Secure database created at: $secureDbPath\n";
    echo "   ✓ Passwords hashed with bcrypt/argon2id\n";
    echo "   ✓ Audit triggers installed\n";
    echo "   ✓ File permissions set to 0600\n\n";
    
} catch (Exception $e) {
    echo "   ✗ Error: " . $e->getMessage() . "\n";
    exit(1);
}

echo "=== Setup Complete! ===\n\n";
echo "Test accounts:\n";
echo "  Username: admin    Password: admin123\n";
echo "  Username: user1    Password: password1\n";
echo "  Username: user2    Password: password2\n\n";
echo "To run vulnerable version: cd vulnerable && php -S localhost:8080\n";
echo "To run secure version:     cd secure && php -S localhost:8081\n";
