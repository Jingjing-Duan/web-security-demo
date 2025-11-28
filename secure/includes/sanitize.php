<?php
/**
 * SECURE Input Sanitization Functions
 * 
 * SECURITY FEATURES:
 * - XSS prevention through output encoding
 * - Input validation and sanitization
 * - Type-specific sanitizers
 */

/**
 * Sanitize string input for storage
 * Removes potential harmful content before database storage
 */
function sanitize_input(string $data): string {
    $data = trim($data);           // Remove whitespace
    $data = stripslashes($data);   // Remove backslashes
    return $data;
}

/**
 * Encode output for HTML display (XSS Prevention)
 * ALWAYS use this when displaying user-generated content
 */
function encode_output(string $data): string {
    return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Comprehensive sanitization function
 * Combines multiple sanitization techniques
 */
function sanitize(string $data, bool $stripTags = false): string {
    $data = trim($data);
    $data = stripslashes($data);
    
    if ($stripTags) {
        $data = strip_tags($data);
    }
    
    return $data;
}

/**
 * Validate and sanitize email
 */
function sanitize_email(string $email): ?string {
    $email = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
    
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return $email;
    }
    
    return null;
}

/**
 * Validate and sanitize integer
 */
function sanitize_int($value): ?int {
    $value = filter_var($value, FILTER_VALIDATE_INT);
    return $value !== false ? $value : null;
}

/**
 * Validate and sanitize username
 * Only allows alphanumeric characters and underscores
 */
function sanitize_username(string $username): ?string {
    $username = trim($username);
    
    // Only allow alphanumeric and underscores, 3-30 chars
    if (preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
        return $username;
    }
    
    return null;
}

/**
 * Validate URL
 */
function sanitize_url(string $url): ?string {
    $url = filter_var(trim($url), FILTER_SANITIZE_URL);
    
    if (filter_var($url, FILTER_VALIDATE_URL)) {
        return $url;
    }
    
    return null;
}

/**
 * Sanitize for SQL LIKE queries (escape % and _)
 */
function sanitize_like(string $value): string {
    return addcslashes($value, '%_');
}

/**
 * Validate file upload
 */
function validate_file_upload(array $file, array $allowedTypes, int $maxSize): array {
    $errors = [];
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = 'File upload failed';
        return $errors;
    }
    
    if ($file['size'] > $maxSize) {
        $errors[] = 'File size exceeds limit';
    }
    
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($file['tmp_name']);
    
    if (!in_array($mimeType, $allowedTypes)) {
        $errors[] = 'Invalid file type';
    }
    
    return $errors;
}

/**
 * Create safe filename
 */
function safe_filename(string $filename): string {
    // Remove any path components
    $filename = basename($filename);
    
    // Replace spaces and special chars
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);
    
    // Prevent double extensions
    $filename = preg_replace('/\.+/', '.', $filename);
    
    return $filename;
}

/**
 * Validate date format
 */
function validate_date(string $date, string $format = 'Y-m-d'): bool {
    $d = DateTime::createFromFormat($format, $date);
    return $d && $d->format($format) === $date;
}

/**
 * Strip all HTML tags (for plain text only content)
 */
function strip_all_html(string $data): string {
    return strip_tags($data);
}

/**
 * Allow only specific HTML tags (for rich text)
 */
function allow_safe_html(string $data): string {
    $allowedTags = '<p><br><strong><em><ul><ol><li><a>';
    return strip_tags($data, $allowedTags);
}
