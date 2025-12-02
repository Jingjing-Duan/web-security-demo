<?php
/**
 * SECURE Cryptography Functions
 * 
 * SECURITY FEATURES:
 * - AES-256-GCM authenticated encryption (via OpenSSL or Sodium)
 * - Proper key derivation
 * - Secure random number generation
 * - HMAC for integrity verification
 */

// Encryption key - PRODUCTION: Use environment variable or secret manager
// FALLBACK: For demo/development, use file-based key (excluded from backups)
define('ENCRYPTION_KEY_FILE', __DIR__ . '/../../data/.encryption_key');

/**
 * Get encryption key from environment variable or file fallback
 *
 * PRODUCTION: Set ENCRYPTION_KEY environment variable (base64-encoded 32-byte key)
 * Example: export ENCRYPTION_KEY=$(openssl rand -base64 32)
 */
function get_encryption_key(): string {
    // PRODUCTION: Use environment variable
    if (!empty($_ENV['ENCRYPTION_KEY'])) {
        $key = base64_decode($_ENV['ENCRYPTION_KEY']);
        if ($key !== false && strlen($key) === 32) {
            return $key;
        }
        error_log('WARNING: ENCRYPTION_KEY environment variable is invalid (must be base64-encoded 32 bytes)');
    }

    // FALLBACK: Use file-based key for development/demo
    // Note: This file should be excluded from backups and version control
    if (file_exists(ENCRYPTION_KEY_FILE)) {
        $key = file_get_contents(ENCRYPTION_KEY_FILE);
        if (strlen($key) === 32) {
            return $key;
        }
    }

    // Generate new 256-bit key if none exists
    $key = random_bytes(32);

    // Ensure directory exists
    $dir = dirname(ENCRYPTION_KEY_FILE);
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }

    // Save key securely
    file_put_contents(ENCRYPTION_KEY_FILE, $key);
    chmod(ENCRYPTION_KEY_FILE, 0600);

    error_log('WARNING: Generated new encryption key in file. In production, use ENCRYPTION_KEY environment variable!');

    return $key;
}

/**
 * Encrypt data using AES-256-GCM
 * Returns base64-encoded string containing nonce + tag + ciphertext
 */
function encrypt_data(string $plaintext, ?string $key = null): string {
    $key = $key ?? get_encryption_key();
    
    // Check if Sodium extension is available (preferred)
    if (function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
        return encrypt_with_sodium($plaintext, $key);
    }
    
    // Fallback to OpenSSL AES-256-GCM
    return encrypt_with_openssl($plaintext, $key);
}

/**
 * Decrypt data
 * Accepts base64-encoded string from encrypt_data()
 */
function decrypt_data(string $encrypted, ?string $key = null): ?string {
    $key = $key ?? get_encryption_key();
    
    // Check if Sodium extension is available
    if (function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt')) {
        return decrypt_with_sodium($encrypted, $key);
    }
    
    // Fallback to OpenSSL
    return decrypt_with_openssl($encrypted, $key);
}

/**
 * Encrypt using Sodium (XChaCha20-Poly1305)
 */
function encrypt_with_sodium(string $plaintext, string $key): string {
    // Generate random nonce (24 bytes for XChaCha20)
    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    
    // Encrypt with authentication
    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        $plaintext,
        '',  // Additional data (none)
        $nonce,
        $key
    );
    
    // Combine nonce + ciphertext and encode
    return base64_encode($nonce . $ciphertext);
}

/**
 * Decrypt using Sodium
 */
function decrypt_with_sodium(string $encrypted, string $key): ?string {
    try {
        $decoded = base64_decode($encrypted);
        if ($decoded === false) {
            return null;
        }
        
        $nonceLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        
        if (strlen($decoded) < $nonceLength) {
            return null;
        }
        
        $nonce = substr($decoded, 0, $nonceLength);
        $ciphertext = substr($decoded, $nonceLength);
        
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            '',  // Additional data
            $nonce,
            $key
        );
        
        if ($plaintext === false) {
            return null;
        }
        
        return $plaintext;
        
    } catch (Exception $e) {
        error_log('Sodium decryption failed: ' . $e->getMessage());
        return null;
    }
}

/**
 * Encrypt using OpenSSL AES-256-GCM
 */
function encrypt_with_openssl(string $plaintext, string $key): string {
    $cipher = 'aes-256-gcm';
    $ivLength = openssl_cipher_iv_length($cipher);
    $iv = random_bytes($ivLength);
    $tag = '';
    
    $ciphertext = openssl_encrypt(
        $plaintext,
        $cipher,
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16  // Tag length
    );
    
    if ($ciphertext === false) {
        throw new Exception('Encryption failed');
    }
    
    // Format: iv (12 bytes) + tag (16 bytes) + ciphertext
    return base64_encode($iv . $tag . $ciphertext);
}

/**
 * Decrypt using OpenSSL AES-256-GCM
 */
function decrypt_with_openssl(string $encrypted, string $key): ?string {
    try {
        $decoded = base64_decode($encrypted);
        if ($decoded === false) {
            return null;
        }
        
        $cipher = 'aes-256-gcm';
        $ivLength = openssl_cipher_iv_length($cipher);
        $tagLength = 16;
        
        if (strlen($decoded) < $ivLength + $tagLength) {
            return null;
        }
        
        $iv = substr($decoded, 0, $ivLength);
        $tag = substr($decoded, $ivLength, $tagLength);
        $ciphertext = substr($decoded, $ivLength + $tagLength);
        
        $plaintext = openssl_decrypt(
            $ciphertext,
            $cipher,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($plaintext === false) {
            return null;
        }
        
        return $plaintext;
        
    } catch (Exception $e) {
        error_log('OpenSSL decryption failed: ' . $e->getMessage());
        return null;
    }
}

/**
 * Generate secure random token
 */
function generate_secure_token(int $length = 32): string {
    return bin2hex(random_bytes($length));
}

/**
 * Generate secure random bytes
 */
function secure_random_bytes(int $length): string {
    return random_bytes($length);
}

/**
 * Create HMAC signature
 */
function create_hmac(string $data, string $key): string {
    return hash_hmac('sha256', $data, $key);
}

/**
 * Verify HMAC signature (timing-safe)
 */
function verify_hmac(string $data, string $signature, string $key): bool {
    $expected = hash_hmac('sha256', $data, $key);
    return hash_equals($expected, $signature);
}

/**
 * Derive key from password (for user-provided keys)
 */
function derive_key(string $password, string $salt, int $length = 32): string {
    // Use Argon2id if available
    if (defined('PASSWORD_ARGON2ID')) {
        return sodium_crypto_pwhash(
            $length,
            $password,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
    }
    
    // Fallback to PBKDF2
    return hash_pbkdf2('sha256', $password, $salt, 100000, $length, true);
}

/**
 * Generate salt for key derivation
 */
function generate_salt(): string {
    if (defined('SODIUM_CRYPTO_PWHASH_SALTBYTES')) {
        return random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    }
    return random_bytes(16);
}
