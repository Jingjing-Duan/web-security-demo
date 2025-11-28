<?php
/**
 * VULNERABLE Comments Page
 * 
 * SECURITY ISSUES:
 * 1. Stored XSS - User input displayed without encoding
 * 2. SQL Injection in comment insertion
 * 3. No access control - users can see all comments
 * 4. No CSRF protection
 */
session_start();

// Check if logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php?error=Please login first');
    exit;
}

require_once 'includes/db.php';

$error = '';
$success = '';

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
    // VULNERABLE: No input sanitization!
    $comment = $_POST['comment'];
    $user_id = $_SESSION['user_id'];
    
    // VULNERABLE: SQL Injection possible!
    $query = "INSERT INTO comments (user_id, content) VALUES ($user_id, '$comment')";
    
    if ($db->exec($query)) {
        $success = 'Comment posted successfully!';
    } else {
        $error = 'Failed to post comment: ' . $db->lastErrorMsg();
    }
}

// Handle comment deletion (VULNERABLE: No ownership check!)
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    // VULNERABLE: Anyone can delete any comment!
    $db->exec("DELETE FROM comments WHERE id = $id");
    header('Location: comments.php?deleted=1');
    exit;
}

// Fetch all comments
$comments = $db->query("
    SELECT c.*, u.username 
    FROM comments c 
    JOIN users u ON c.user_id = u.id 
    ORDER BY c.created_at DESC
");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comments - Vulnerable Demo</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header class="vulnerable">
            <h1>💬 Comment System <span class="badge badge-danger">VULNERABLE</span></h1>
            <p>This version is vulnerable to Cross-Site Scripting (XSS)</p>
        </header>

        <nav>
            <div>
                <a href="comments.php">Comments</a>
                <a href="index.php">Home</a>
            </div>
            <div class="user-info">
                Logged in as: <strong><?php echo $_SESSION['username']; ?></strong>
                | <a href="logout.php">Logout</a>
            </div>
        </nav>

        <div class="warning-box">
            <h3>⚠️ XSS Vulnerability Demo</h3>
            <p>Try posting these malicious comments:</p>
            <ul style="margin: 10px 0 0 20px;">
                <li><code>&lt;script&gt;alert('XSS!')&lt;/script&gt;</code></li>
                <li><code>&lt;img src=x onerror="alert('Hacked!')"&gt;</code></li>
                <li><code>&lt;a href="javascript:alert(document.cookie)"&gt;Click me&lt;/a&gt;</code></li>
            </ul>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo $success; ?></div>
        <?php endif; ?>
        
        <?php if (isset($_GET['deleted'])): ?>
            <div class="alert alert-info">Comment deleted.</div>
        <?php endif; ?>

        <div class="card">
            <h2>Post a Comment</h2>
            <form action="comments.php" method="POST">
                <div class="form-group">
                    <label for="comment">Your Comment</label>
                    <textarea id="comment" name="comment" required
                              placeholder="Write your comment here... (try injecting scripts!)"></textarea>
                </div>
                <button type="submit" class="btn btn-danger">Post Comment (No Sanitization)</button>
            </form>
        </div>

        <div class="card">
            <h2>All Comments</h2>
            
            <?php 
            $hasComments = false;
            while ($comment = $comments->fetchArray(SQLITE3_ASSOC)): 
                $hasComments = true;
            ?>
                <div class="comment">
                    <div class="comment-header">
                        <span class="comment-author"><?php echo $comment['username']; ?></span>
                        <span class="comment-date"><?php echo $comment['created_at']; ?></span>
                    </div>
                    <div class="comment-content">
                        <?php 
                        // VULNERABLE: Direct output without htmlspecialchars!
                        // This allows stored XSS attacks
                        echo $comment['content']; 
                        ?>
                    </div>
                    <div class="comment-actions">
                        <!-- VULNERABLE: No ownership check, anyone can delete -->
                        <a href="comments.php?delete=<?php echo $comment['id']; ?>" 
                           class="btn btn-sm btn-secondary"
                           onclick="return confirm('Delete this comment?')">Delete</a>
                    </div>
                </div>
            <?php endwhile; ?>
            
            <?php if (!$hasComments): ?>
                <p style="color: #888; text-align: center; padding: 20px;">
                    No comments yet. Be the first to post!
                </p>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2>Vulnerability Explanation</h2>
            <p>Comments are displayed without encoding:</p>
            <pre>echo $comment['content'];  // VULNERABLE!</pre>
            <p style="margin-top: 15px;">
                The fix would use <code>htmlspecialchars()</code>:
            </p>
            <pre>echo htmlspecialchars($comment['content'], ENT_QUOTES, 'UTF-8');</pre>
        </div>

        <footer>
            <p>Web Security Demo - Algonquin College</p>
            <p><a href="../secure/comments.php">Switch to Secure Version</a></p>
        </footer>
    </div>
</body>
</html>
