<?php
/**
 * SECURE Registration Page
 * 
 * SECURITY FEATURES:
 * 1. CSRF token protection
 * 2. PDO prepared statements
 * 3. Password hashing with Argon2ID/Bcrypt
 * 4. Input validation and sanitization
 * 5. Password strength requirements
 * 6. Email encryption
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/sanitize.php';
require_once 'includes/crypto.php';

init_secure_session();

// Redirect if already logged in
if (is_logged_in()) {
    header('Location: comments.php');
    exit;
}

$csrf_token = generate_csrf_token();
$error = '';
$success = '';
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please try again.';
    } else {
        // Get and validate input
        $username = sanitize_username($_POST['username'] ?? '');
        $email = sanitize_email($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $password_confirm = $_POST['password_confirm'] ?? '';
        
        // Validation
        if (!$username) {
            $errors[] = 'Username must be 3-30 characters (letters, numbers, underscores only)';
        }
        
        if (!empty($_POST['email']) && !$email) {
            $errors[] = 'Invalid email format';
        }
        
        if ($password !== $password_confirm) {
            $errors[] = 'Passwords do not match';
        }
        
        // Password strength validation
        $passwordErrors = validate_password_strength($password);
        $errors = array_merge($errors, $passwordErrors);
        
        // Check if username exists
        if ($username && empty($errors)) {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :username");
            $stmt->execute([':username' => $username]);
            if ($stmt->fetch()) {
                $errors[] = 'Username already exists';
            }
        }
        
        // Create user if no errors
        if (empty($errors)) {
            try {
                // SECURE: Hash password
                $passwordHash = hash_password($password);
                
                // SECURE: Encrypt email (optional sensitive data encryption)
                $encryptedEmail = $email ? encrypt_data($email) : null;
                
                // SECURE: Use prepared statement
                $stmt = $pdo->prepare("
                    INSERT INTO users (username, password_hash, email_encrypted, role) 
                    VALUES (:username, :hash, :email, 'user')
                ");
                
                $stmt->execute([
                    ':username' => $username,
                    ':hash' => $passwordHash,
                    ':email' => $encryptedEmail
                ]);
                
                $success = 'Registration successful! You can now login.';
                
                // Log registration
                error_log("New user registered: $username from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                
            } catch (PDOException $e) {
                error_log('Registration error: ' . $e->getMessage());
                $error = 'Registration failed. Please try again.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Secure Demo</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header class="secure">
            <h1>🔒 Registration <span class="badge badge-success">SECURE</span></h1>
            <p>Passwords are securely hashed before storage</p>
        </header>

        <div class="security-box">
            <h3>✅ Security Features</h3>
            <ul>
                <li>Passwords hashed with Argon2ID (or Bcrypt fallback)</li>
                <li>Password strength requirements enforced</li>
                <li>Email addresses encrypted at rest</li>
                <li>CSRF token protection</li>
                <li>Input validation and sanitization</li>
            </ul>
        </div>

        <div class="card">
            <h2>Create Account</h2>
            
            <?php if ($error): ?>
                <div class="alert alert-danger"><?php echo encode_output($error); ?></div>
            <?php endif; ?>
            
            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <ul style="margin: 0; padding-left: 20px;">
                        <?php foreach ($errors as $err): ?>
                            <li><?php echo encode_output($err); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo encode_output($success); ?></div>
            <?php endif; ?>

            <form action="register.php" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required
                           placeholder="3-30 characters (letters, numbers, underscores)"
                           pattern="[a-zA-Z0-9_]{3,30}"
                           autocomplete="username">
                </div>
                
                <div class="form-group">
                    <label for="email">Email (Optional)</label>
                    <input type="email" id="email" name="email"
                           placeholder="Will be encrypted at rest"
                           autocomplete="email">
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required
                           placeholder="Min 8 chars with uppercase, lowercase, number"
                           autocomplete="new-password">
                    <small style="color: #666;">
                        Requirements: 8+ characters, uppercase, lowercase, and number
                    </small>
                </div>
                
                <div class="form-group">
                    <label for="password_confirm">Confirm Password</label>
                    <input type="password" id="password_confirm" name="password_confirm" required
                           placeholder="Re-enter password"
                           autocomplete="new-password">
                </div>
                
                <button type="submit" class="btn btn-success">Register (Secure)</button>
            </form>
            
            <p style="margin-top: 20px;">
                Already have an account? <a href="index.php">Login here</a>
            </p>
        </div>

        <div class="card">
            <h2>How Passwords Are Stored</h2>
            <p>Passwords are hashed using Argon2ID before storage:</p>
            <pre>$hash = password_hash($password, PASSWORD_ARGON2ID);
// Result: $argon2id$v=19$m=65536,t=4,p=3$...</pre>
            <p style="margin-top: 15px; color: #27ae60;">
                <strong>Benefit:</strong> Even if the database is compromised, passwords cannot be recovered!
            </p>
        </div>

        <footer>
            <p>Web Security Demo - Algonquin College</p>
            <p><a href="../vulnerable/register.php">Switch to Vulnerable Registration</a></p>
        </footer>
    </div>
</body>
</html>
