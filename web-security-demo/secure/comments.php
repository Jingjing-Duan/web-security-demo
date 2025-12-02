<?php
/**
 * SECURE Comments Page
 * 
 * SECURITY FEATURES:
 * 1. XSS prevention with output encoding
 * 2. PDO prepared statements
 * 3. CSRF token protection
 * 4. Row-level access control (users can only edit/delete their own comments)
 * 5. Input sanitization
 * 6. Audit logging via database triggers
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/sanitize.php';
require_once 'includes/crypto.php';

init_secure_session();
require_login();

$csrf_token = generate_csrf_token();
$error = '';
$success = '';
$user_id = get_current_user_id();
$username = get_current_username();

$search = $_GET['search'] ?? '';
$isSearching = !empty($search);

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
    // Verify CSRF token
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please try again.';
    } else {
        // SECURE: Sanitize input
        $comment = sanitize_input($_POST['comment']);
        
        if (empty($comment)) {
            $error = 'Comment cannot be empty.';
        } elseif (strlen($comment) > 1000) {
            $error = 'Comment too long (max 1000 characters).';
        } else {
            try {
                // SECURE: Encrypt PII (comment content) using AEAD
                $encrypted_comment = encrypt_data($comment);

                // SECURE: Use prepared statement
                $stmt = $pdo->prepare("INSERT INTO comments (user_id, content, content_encrypted) VALUES (:user_id, :content, :encrypted)");
                $stmt->execute([
                    ':user_id' => $user_id,
                    ':content' => $comment,
                    ':encrypted' => $encrypted_comment
                ]);
                $success = 'Comment posted successfully!';
            } catch (PDOException $e) {
                error_log('Comment insert error: ' . $e->getMessage());
                $error = 'Failed to post comment. Please try again.';
            }
        }
    }
}

// Handle comment deletion with ownership check
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $delete_id = sanitize_int($_POST['delete_id']);
        
        if ($delete_id) {
            try {
                // SECURE: Row-level security - only allow deletion of own comments (or admin)
                if (is_admin()) {
                    $stmt = $pdo->prepare("DELETE FROM comments WHERE id = :id");
                    $stmt->execute([':id' => $delete_id]);
                } else {
                    $stmt = $pdo->prepare("DELETE FROM comments WHERE id = :id AND user_id = :user_id");
                    $stmt->execute([':id' => $delete_id, ':user_id' => $user_id]);
                }
                
                if ($stmt->rowCount() > 0) {
                    $success = 'Comment deleted.';
                } else {
                    $error = 'Cannot delete this comment.';
                }
            } catch (PDOException $e) {
                error_log('Comment delete error: ' . $e->getMessage());
                $error = 'Failed to delete comment.';
            }
        }
    }
}

// Fetch comments (supports search)
try {
    if ($isSearching) {
        // SECURE: Search with prepared statements + wildcard
        $stmt = $pdo->prepare("
            SELECT c.id, c.content, c.created_at, c.user_id, u.username 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.content LIKE :search
            ORDER BY c.created_at DESC
        ");
        $stmt->execute([
            ':search' => '%' . $search . '%'
        ]);
    } else {
        // SECURE: Fetch all comments
        $stmt = $pdo->query("
            SELECT c.id, c.content, c.created_at, c.user_id, u.username 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            ORDER BY c.created_at DESC
        ");
    }

    $comments = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log('Comment fetch error: ' . $e->getMessage());
    $comments = [];
}

// Fetch recent audit log entries
try {
    $auditStmt = $pdo->query("
        SELECT * FROM audit_log 
        WHERE table_name = 'comments' 
        ORDER BY created_at DESC 
        LIMIT 5
    ");
    $auditLog = $auditStmt->fetchAll();
} catch (PDOException $e) {
    $auditLog = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comments - Secure Demo</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header class="secure">
            <h1>💬 Comment System <span class="badge badge-success">SECURE</span></h1>
            <p>XSS attacks are prevented with output encoding</p>
        </header>

        <nav>
            <div>
                <a href="comments.php">Comments</a>
                <a href="audit.php">Audit Log</a>
                <a href="index.php">Home</a>
            </div>
            <div class="user-info">
                Logged in as: <strong><?php echo encode_output($username); ?></strong>
                <?php if (is_admin()): ?><span class="badge badge-success">Admin</span><?php endif; ?>
                | <a href="logout.php">Logout</a>
            </div>
        </nav>

        <div class="security-box">
            <h3>✅ Security Features Active</h3>
            <ul>
                <li>Output encoding prevents XSS attacks</li>
                <li>CSRF tokens protect against forged requests</li>
                <li>Users can only delete their own comments</li>
                <li>All actions are audit logged</li>
                <li>Comments encrypted at rest using AEAD (XChaCha20-Poly1305/AES-256-GCM)</li>
            </ul>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo encode_output($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo encode_output($success); ?></div>
        <?php endif; ?>

        <!-- SEARCH BAR -->
        <div class="card">
            <h2>Search Comments (Secure)</h2>
            <form method="GET">
                <div class="form-group">
                    <label>Search term:</label>
                    <input type="text" name="search" 
                        value="<?= htmlspecialchars($search) ?>"
                        placeholder="Search safely...">
                </div>
                <button type="submit" class="btn btn-success">Search (Safe)</button>
            </form>
        </div>     

        <div class="card">
            <h2>Post a Comment</h2>
            <form action="comments.php" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="form-group">
                    <label for="comment">Your Comment</label>
                    <textarea id="comment" name="comment" required
                              maxlength="1000"
                              placeholder="Write your comment here... (scripts will be escaped!)"></textarea>
                    <small style="color: #666;">Max 1000 characters. HTML will be escaped.</small>
                </div>
                <button type="submit" class="btn btn-success">Post Comment (XSS Protected)</button>
            </form>
        </div>

        <div class="card">
            <h2>All Comments</h2>
            
            <?php if (empty($comments)): ?>
                <p style="color: #888; text-align: center; padding: 20px;">
                    No comments yet. Be the first to post!
                </p>
            <?php else: ?>
                <?php foreach ($comments as $comment): ?>
                    <div class="comment">
                        <div class="comment-header">
                            <span class="comment-author">
                                <?php echo encode_output($comment['username']); ?>
                            </span>
                            <span class="comment-date">
                                <?php echo encode_output($comment['created_at']); ?>
                            </span>
                        </div>
                        <div class="comment-content">
                            <?php 
                            // SECURE: Output encoding prevents XSS!
                            // Try posting <script>alert('xss')</script> - it will be displayed as text
                            echo encode_output($comment['content']); 
                            ?>
                        </div>
                        <?php if ($comment['user_id'] == $user_id || is_admin()): ?>
                        <div class="comment-actions">
                            <!-- SECURE: CSRF-protected deletion form -->
                            <form action="comments.php" method="POST" style="display: inline;">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <input type="hidden" name="delete_id" value="<?php echo $comment['id']; ?>">
                                <button type="submit" class="btn btn-sm btn-secondary"
                                        onclick="return confirm('Delete this comment?')">Delete</button>
                            </form>
                        </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <?php if (!empty($auditLog)): ?>
        <div class="card">
            <h2>Recent Audit Log</h2>
            <table class="audit-table">
                <thead>
                    <tr>
                        <th>Action</th>
                        <th>Record ID</th>
                        <th>User ID</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($auditLog as $log): ?>
                    <tr>
                        <td><?php echo encode_output($log['action']); ?></td>
                        <td><?php echo encode_output($log['record_id']); ?></td>
                        <td><?php echo encode_output($log['user_id'] ?? 'N/A'); ?></td>
                        <td><?php echo encode_output($log['created_at']); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p style="margin-top: 10px;"><a href="audit.php">View full audit log →</a></p>
        </div>
        <?php endif; ?>

        <div class="card">
            <h2>How XSS Is Prevented</h2>
            <p>All output is encoded using <code>htmlspecialchars()</code>:</p>
            <pre>echo htmlspecialchars($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');</pre>
            <p style="margin-top: 15px;">
                This converts <code>&lt;script&gt;</code> to <code>&amp;lt;script&amp;gt;</code>, 
                rendering it as harmless text.
            </p>
        </div>

        <footer>
            <p>Web Security Demo - Algonquin College</p>
            <p><a href="../vulnerable/comments.php">Switch to Vulnerable Version</a></p>
        </footer>
    </div>
</body>
</html>
