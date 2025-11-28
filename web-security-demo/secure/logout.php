<?php
/**
 * SECURE Logout Handler
 * 
 * SECURITY FEATURES:
 * 1. Complete session destruction
 * 2. Session cookie invalidation
 * 3. Proper redirect
 */
require_once 'includes/auth.php';

init_secure_session();

// Log the logout
if (isset($_SESSION['username'])) {
    error_log("User logged out: {$_SESSION['username']} from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}

// SECURE: Properly destroy session and cookies
logout_user();

// Redirect to login page
header('Location: index.php?error=' . urlencode('You have been securely logged out.'));
exit;
