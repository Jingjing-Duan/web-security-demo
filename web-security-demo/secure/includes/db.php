<?php
/**
 * SECURE Database Connection
 * 
 * SECURITY FEATURES:
 * - Database stored OUTSIDE public webroot
 * - Uses PDO with prepared statements
 * - Proper error handling (exceptions)
 * - Connection settings for security
 */

// Database path OUTSIDE webroot - SECURE!
$db_path = __DIR__ . '/../../data/secure_database.sqlite';

try {
    // Create PDO connection with secure settings
    $pdo = new PDO('sqlite:' . $db_path);
    
    // Set error mode to exceptions
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Disable emulated prepared statements for true prepared statements
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    
    // Return results as associative arrays by default
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    // Log error but don't expose details to user
    error_log('Database connection failed: ' . $e->getMessage());
    die('A database error occurred. Please try again later.');
}
