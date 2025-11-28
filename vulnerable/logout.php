<?php
/**
 * VULNERABLE Logout
 * 
 * SECURITY ISSUES:
 * 1. Session not properly destroyed
 * 2. Session cookie not invalidated
 * 3. No CSRF protection
 */
session_start();

// VULNERABLE: Only unsetting variables, not destroying session properly
$_SESSION = array();

// VULNERABLE: Not deleting session cookie
// VULNERABLE: Not regenerating session ID

session_destroy();

header('Location: index.php?error=You have been logged out');
exit;
