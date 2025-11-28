<?php
/**
 * VULNERABLE Login Page
 * Demonstrates SQL Injection vulnerability
 */
session_start();

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: comments.php');
    exit;
}

$error = $_GET['error'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Vulnerable Demo</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header class="vulnerable">
            <h1>🔓 Login System <span class="badge badge-danger">VULNERABLE</span></h1>
            <p>This version demonstrates common security vulnerabilities</p>
        </header>

        <div class="warning-box">
            <h3>⚠️ Security Warning</h3>
            <p>This login form is vulnerable to <strong>SQL Injection</strong>. Try these attack payloads:</p>
            <ul style="margin: 10px 0 0 20px;">
                <li>Username: <code>' OR '1'='1' --</code></li>
                <li>Username: <code>admin'--</code></li>
                <li>Username: <code>' UNION SELECT 1,username,password FROM users--</code></li>
            </ul>
        </div>

        <div class="card">
            <h2>Login</h2>
            
            <?php if ($error): ?>
                <div class="alert alert-danger"><?php echo $error; ?></div>
            <?php endif; ?>

            <form action="login.php" method="POST">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required 
                           placeholder="Enter username (try SQL injection!)">
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required
                           placeholder="Enter password">
                </div>
                
                <button type="submit" class="btn btn-danger">Login (Vulnerable)</button>
            </form>
            
            <p style="margin-top: 20px;">
                Don't have an account? <a href="register.php">Register here</a>
            </p>
        </div>

        <div class="card">
            <h2>Vulnerability Details</h2>
            <p>The login handler uses string concatenation to build SQL queries:</p>
            <pre>$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";</pre>
            <p style="margin-top: 15px;">This allows attackers to manipulate the query structure by injecting SQL code through the input fields.</p>
        </div>

        <footer>
            <p>Web Security Demo - Algonquin College</p>
            <p><a href="../secure/">Switch to Secure Version</a></p>
        </footer>
    </div>
</body>
</html>
