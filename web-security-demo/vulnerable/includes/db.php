<?php
/**
 * VULNERABLE Database Connection
 * 
 * SECURITY ISSUES:
 * - Database stored in public webroot (can be downloaded!)
 * - No error handling
 * - Direct SQLite3 usage without PDO
 */

// Database file in public webroot - VULNERABLE!
$db_path = __DIR__ . '/../db/database.sqlite';

// Simple connection without error handling
$db = new SQLite3($db_path);

// No additional security configurations
