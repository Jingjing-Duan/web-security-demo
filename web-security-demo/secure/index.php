<?php
/**
 * SECURE Login Page
 * Demonstrates proper authentication practices
 */
require_once 'includes/auth.php';
require_once 'includes/sanitize.php';

init_secure_session();

// Redirect if already logged in
if (is_logged_in()) {
    header('Location: comments.php');
    exit;
}

$csrf_token = generate_csrf_token();
$error = isset($_GET['error']) ? encode_output($_GET['error']) : '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Secure Demo</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header class="secure">
            <h1>🔒 Login System <span class="badge badge-success">SECURE</span></h1>
            <p>This version implements proper security measures</p>
        </header>

        <div class="security-box">
            <h3>✅ Security Features</h3>
            <ul>
                <li>PDO prepared statements (SQL Injection prevention)</li>
                <li>Password hashing with Argon2ID/Bcrypt</li>
                <li>CSRF token protection</li>
                <li>Secure session management</li>
                <li>HttpOnly, Secure, SameSite cookie flags</li>
            </ul>
        </div>

        <div class="card">
            <h2>Login</h2>
            
            <?php if ($error): ?>
                <div class="alert alert-danger"><?php echo $error; ?></div>
            <?php endif; ?>

            <form action="login.php" method="POST">
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required 
                           placeholder="Enter username"
                           autocomplete="username">
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required
                           placeholder="Enter password"
                           autocomplete="current-password">
                </div>
                
                <button type="submit" class="btn btn-success">Login (Secure)</button>
            </form>
            
            <p style="margin-top: 20px;">
                Don't have an account? <a href="register.php">Register here</a>
            </p>
        </div>

        <div class="card">
            <h2>How It Works</h2>
            <p>The secure login uses prepared statements:</p>
            <pre>$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute([':username' => $username]);</pre>
            <p style="margin-top: 15px;">
                Passwords are verified using <code>password_verify()</code> against the stored hash.
            </p>
        </div>

        <footer>
            <p>Web Security Demo - Algonquin College</p>
            <p><a href="../vulnerable/">Switch to Vulnerable Version</a></p>
        </footer>
    </div>
</body>
</html>
