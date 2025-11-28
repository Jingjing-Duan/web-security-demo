<?php
/**
 * SECURE Login Handler
 * 
 * SECURITY FEATURES:
 * 1. CSRF token verification
 * 2. PDO prepared statements (SQL Injection prevention)
 * 3. Password verification with timing-safe comparison
 * 4. Session regeneration after login
 * 5. Generic error messages (no username enumeration)
 * 6. Password rehashing for algorithm upgrades
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/sanitize.php';

init_secure_session();

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

// Verify CSRF token
$csrf_token = $_POST['csrf_token'] ?? '';
if (!verify_csrf_token($csrf_token)) {
    header('Location: index.php?error=' . urlencode('Invalid request. Please try again.'));
    exit;
}

// Get and sanitize input
$username = sanitize_input($_POST['username'] ?? '');
$password = $_POST['password'] ?? ''; // Don't trim password - spaces might be intentional

// Basic validation
if (empty($username) || empty($password)) {
    header('Location: index.php?error=' . urlencode('Please enter both username and password.'));
    exit;
}

try {
    // SECURE: Use prepared statement with parameterized query
    $stmt = $pdo->prepare("SELECT id, username, password_hash, role FROM users WHERE username = :username");
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch();
    
    // SECURE: Use generic error message (prevents username enumeration)
    $errorMessage = 'Invalid username or password.';
    
    if ($user) {
        // SECURE: Verify password using timing-safe comparison
        if (verify_password($password, $user['password_hash'])) {
            
            // Check if password needs rehashing (algorithm upgrade)
            if (needs_rehash($user['password_hash'])) {
                $newHash = hash_password($password);
                $updateStmt = $pdo->prepare("UPDATE users SET password_hash = :hash, updated_at = CURRENT_TIMESTAMP WHERE id = :id");
                $updateStmt->execute([':hash' => $newHash, ':id' => $user['id']]);
            }
            
            // SECURE: Login with session regeneration
            login_user($user['id'], $user['username'], $user['role']);
            
            // Log successful login
            error_log("Successful login for user: {$user['username']} from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            
            header('Location: comments.php');
            exit;
        }
    }
    
    // SECURE: Same error for both invalid username and invalid password
    // This prevents attackers from enumerating valid usernames
    error_log("Failed login attempt for username: $username from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    
    header('Location: index.php?error=' . urlencode($errorMessage));
    exit;
    
} catch (PDOException $e) {
    // SECURE: Log error but show generic message to user
    error_log('Login error: ' . $e->getMessage());
    header('Location: index.php?error=' . urlencode('An error occurred. Please try again.'));
    exit;
}
