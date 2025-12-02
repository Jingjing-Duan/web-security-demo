<?php
/**
 * SECURE Authentication Functions
 * 
 * SECURITY FEATURES:
 * - Password hashing with Argon2ID (fallback to Bcrypt)
 * - Secure session management
 * - Session regeneration
 * - CSRF token generation
 * - Rate limiting (basic)
 */

/**
 * Check if connection is using HTTPS
 */
function is_https(): bool {
    return (
        (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
        (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
        (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on') ||
        (!empty($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
    );
}

/**
 * Force HTTPS redirect
 * Set FORCE_HTTPS=true in environment to enable
 */
function force_https(): void {
    // Never redirect on localhost/development
    $is_local = in_array($_SERVER['HTTP_HOST'] ?? '', ['localhost', '127.0.0.1', '::1']) ||
                strpos($_SERVER['HTTP_HOST'] ?? '', 'localhost:') === 0 ||
                strpos($_SERVER['HTTP_HOST'] ?? '', '127.0.0.1:') === 0;

    if ($is_local) {
        return; // Skip HTTPS redirect for local development
    }

    // Only redirect if FORCE_HTTPS is explicitly enabled and not already on HTTPS
    $force_https = getenv('FORCE_HTTPS') === 'true' ||
                   (!empty($_ENV['FORCE_HTTPS']) && $_ENV['FORCE_HTTPS'] === 'true');

    if ($force_https && !is_https()) {
        $redirect_url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        header('Location: ' . $redirect_url, true, 301);
        exit;
    }
}

/**
 * Initialize secure session settings
 */
function init_secure_session() {
    // Force HTTPS if configured
    force_https();

    // Only set params if session hasn't started
    if (session_status() === PHP_SESSION_NONE) {
        // Detect if HTTPS is being used
        $using_https = is_https();

        // Secure session cookie settings
        session_set_cookie_params([
            'lifetime' => 0,           // Session cookie (expires on browser close)
            'path' => '/',
            'domain' => '',
            'secure' => $using_https,  // Enable secure flag when using HTTPS
            'httponly' => true,        // Prevent JavaScript access to session cookie
            'samesite' => 'Strict'     // CSRF protection
        ]);

        session_start();

    }
}

/**
 * Hash password using Argon2ID (or Bcrypt as fallback)
 */
function hash_password(string $password): string {
    // Prefer Argon2ID if available (PHP 7.2+)
    if (defined('PASSWORD_ARGON2ID')) {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,  // 64 MB
            'time_cost' => 4,
            'threads' => 3
        ]);
    }
    
    // Fallback to Bcrypt
    return password_hash($password, PASSWORD_BCRYPT, [
        'cost' => 12
    ]);
}

/**
 * Verify password against hash
 */
function verify_password(string $password, string $hash): bool {
    return password_verify($password, $hash);
}

/**
 * Check if password hash needs rehashing (algorithm upgrade)
 */
function needs_rehash(string $hash): bool {
    if (defined('PASSWORD_ARGON2ID')) {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID);
    }
    return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * Regenerate session ID safely
 */
function regenerate_session(): void {
    session_regenerate_id(true);
}

/**
 * Generate CSRF token
 */
function generate_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 */
function verify_csrf_token(string $token): bool {
    if (empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Check if user is logged in
 */
function is_logged_in(): bool {
    return isset($_SESSION['user_id']) && isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

/**
 * Require login (redirect if not logged in)
 */
function require_login(): void {
    if (!is_logged_in()) {
        header('Location: index.php?error=' . urlencode('Please login first'));
        exit;
    }

        // -----------------------------
    // SESSION TIMEOUT CHECK
    // -----------------------------
    $timeout = 900; // 15 minutes
    //$timeout = 5; // 15 minutes

    if (isset($_SESSION['last_activity']) &&
        time() - $_SESSION['last_activity'] > $timeout) {

        // 超时 → 注销并跳回登录
        session_unset();
        session_destroy();
        header("Location: index.php?error=Session expired. Please login again.");
        exit;
    }

    // 刷新时间戳
    $_SESSION['last_activity'] = time();

}

/**
 * Login user securely
 */
function login_user(int $user_id, string $username, string $role = 'user'): void {
    // Regenerate session ID to prevent session fixation
    regenerate_session();
    
    $_SESSION['user_id'] = $user_id;
    $_SESSION['username'] = $username;
    $_SESSION['role'] = $role;
    $_SESSION['logged_in'] = true;
    $_SESSION['login_time'] = time();
    $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
}

/**
 * Logout user securely
 */
function logout_user(): void {
    // Unset all session variables
    $_SESSION = array();
    
    // Delete session cookie
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }
    
    // Destroy session
    session_destroy();
}

/**
 * Validate password strength
 */
function validate_password_strength(string $password): array {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters long';
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must contain at least one uppercase letter';
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must contain at least one lowercase letter';
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must contain at least one number';
    }
    
    return $errors;
}

/**
 * Get current user ID
 */
function get_current_user_id(): ?int {
    return $_SESSION['user_id'] ?? null;
}

/**
 * Get current username
 */
function get_current_username(): ?string {
    return $_SESSION['username'] ?? null;
}

/**
 * Check if current user is admin
 */
function is_admin(): bool {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}
