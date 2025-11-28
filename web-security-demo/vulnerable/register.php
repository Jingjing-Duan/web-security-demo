<?php
/**
 * VULNERABLE Registration Page
 * 
 * SECURITY ISSUES:
 * 1. SQL Injection in INSERT statement
 * 2. Plain text password storage
 * 3. No input validation
 * 4. No CSRF protection
 */
session_start();

if (isset($_SESSION['user_id'])) {
    header('Location: comments.php');
    exit;
}

require_once 'includes/db.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get user input - NO SANITIZATION (VULNERABLE!)
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $email = $_POST['email'] ?? '';
    
    // VULNERABLE: No password strength requirements
    // VULNERABLE: No input validation
    
    if (empty($username) || empty($password)) {
        $error = 'Username and password are required';
    } else {
        // VULNERABLE: Plain text password storage!
        // VULNERABLE: SQL Injection possible!
        $query = "INSERT INTO users (username, password, email) VALUES ('$username', '$password', '$email')";
        
        try {
            $result = $db->exec($query);
            if ($result) {
                $success = 'Registration successful! You can now login.';
            } else {
                // VULNERABLE: Exposing database error
                $error = 'Registration failed: ' . $db->lastErrorMsg();
            }
        } catch (Exception $e) {
            $error = 'Error: ' . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Vulnerable Demo</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header class="vulnerable">
            <h1>🔓 Registration <span class="badge badge-danger">VULNERABLE</span></h1>
            <p>This version stores passwords in plain text!</p>
        </header>

        <div class="warning-box">
            <h3>⚠️ Security Issues</h3>
            <ul style="margin: 10px 0 0 20px;">
                <li>Passwords stored in <strong>plain text</strong></li>
                <li>No input validation or sanitization</li>
                <li>SQL Injection possible in registration</li>
                <li>No CSRF token protection</li>
            </ul>
        </div>

        <div class="card">
            <h2>Create Account</h2>
            
            <?php if ($error): ?>
                <div class="alert alert-danger"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo $success; ?></div>
            <?php endif; ?>

            <form action="register.php" method="POST">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required
                           placeholder="Choose a username">
                </div>
                
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email"
                           placeholder="Enter email (optional)">
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required
                           placeholder="Any password works (no requirements!)">
                    <small style="color: #888;">⚠️ Warning: Password will be stored in plain text!</small>
                </div>
                
                <button type="submit" class="btn btn-danger">Register (Insecure)</button>
            </form>
            
            <p style="margin-top: 20px;">
                Already have an account? <a href="index.php">Login here</a>
            </p>
        </div>

        <div class="card">
            <h2>How Passwords Are Stored</h2>
            <p>In the vulnerable version, passwords are stored as-is:</p>
            <pre>INSERT INTO users (username, password) VALUES ('john', 'mypassword123')</pre>
            <p style="margin-top: 15px; color: #e74c3c;">
                <strong>Problem:</strong> If the database is compromised, all passwords are immediately exposed!
            </p>
        </div>

        <footer>
            <p>Web Security Demo - Algonquin College</p>
            <p><a href="../secure/register.php">Switch to Secure Registration</a></p>
        </footer>
    </div>
</body>
</html>
