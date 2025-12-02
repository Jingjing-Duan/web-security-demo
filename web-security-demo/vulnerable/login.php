<?php
/**
 * VULNERABLE Login Handler
 * 
 * SECURITY ISSUES:
 * 1. SQL Injection - Direct string concatenation in query
 * 2. Plain text password comparison
 * 3. No session regeneration
 * 4. Insecure session cookies
 * 5. Verbose error messages
 */
session_start();

require_once 'includes/db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

// Get user input - NO SANITIZATION (VULNERABLE!)
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// VULNERABLE: Direct string concatenation allows SQL Injection!
// An attacker can input: ' OR '1'='1' -- 
// Which makes the query: SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = '...'
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

// Log the query for demonstration purposes
error_log("Vulnerable Query: $query");

try {
    // Execute the vulnerable query
    $result = $db->query($query);
    
    if ($result) {
        $user = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($user) {
            // Login successful - but session handling is INSECURE!
            
            // VULNERABLE: No session regeneration (session fixation attack possible)
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['logged_in'] = true;
            
            // VULNERABLE: No session timeout set
            // VULNERABLE: Cookies not marked HttpOnly or Secure
            
            header('Location: comments.php');
            exit;
        } else {
            // VULNERABLE: Could reveal if username exists
            header('Location: index.php?error=Invalid username or password');
            exit;
        }
    } else {
        // VULNERABLE: Exposing database error to user
        $error = $db->lastErrorMsg();
        header("Location: index.php?error=" . urlencode("Database error") .
            "&sql=" . urlencode($query) .
            "&dberror=" . urlencode($error));
        exit;
    }
} catch (Exception $e) {
    // VULNERABLE: Exposing exception details
    header('Location: index.php?error=Error: ' . urlencode($e->getMessage()));
    exit;
}
