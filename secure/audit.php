<?php
/**
 * SECURE Audit Log Page
 * Displays database audit trail
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/sanitize.php';

init_secure_session();
require_login();

$username = get_current_username();

// Fetch audit log entries
try {
    $stmt = $pdo->query("
        SELECT al.*, u.username 
        FROM audit_log al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC
        LIMIT 100
    ");
    $auditLog = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log('Audit log fetch error: ' . $e->getMessage());
    $auditLog = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Log - Secure Demo</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header class="secure">
            <h1>📋 Audit Log <span class="badge badge-success">SECURE</span></h1>
            <p>Database activity tracking for security monitoring</p>
        </header>

        <nav>
            <div>
                <a href="comments.php">Comments</a>
                <a href="audit.php">Audit Log</a>
                <a href="index.php">Home</a>
            </div>
            <div class="user-info">
                Logged in as: <strong><?php echo encode_output($username); ?></strong>
                | <a href="logout.php">Logout</a>
            </div>
        </nav>

        <div class="security-box">
            <h3>✅ Audit Logging Benefits</h3>
            <ul>
                <li>Track all database modifications</li>
                <li>Detect unauthorized changes</li>
                <li>Support compliance requirements</li>
                <li>Enable forensic analysis</li>
            </ul>
        </div>

        <div class="card">
            <h2>Activity Log (Last 100 entries)</h2>
            
            <?php if (empty($auditLog)): ?>
                <p style="color: #888; text-align: center; padding: 20px;">
                    No audit entries yet.
                </p>
            <?php else: ?>
                <table class="audit-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Table</th>
                            <th>Action</th>
                            <th>Record ID</th>
                            <th>User</th>
                            <th>Old Value</th>
                            <th>New Value</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($auditLog as $log): ?>
                        <tr>
                            <td><?php echo encode_output($log['id']); ?></td>
                            <td><?php echo encode_output($log['table_name']); ?></td>
                            <td>
                                <span class="badge <?php 
                                    echo $log['action'] === 'INSERT' ? 'badge-success' : 
                                        ($log['action'] === 'DELETE' ? 'badge-danger' : ''); 
                                ?>">
                                    <?php echo encode_output($log['action']); ?>
                                </span>
                            </td>
                            <td><?php echo encode_output($log['record_id']); ?></td>
                            <td><?php echo encode_output($log['username'] ?? 'System'); ?></td>
                            <td>
                                <?php if ($log['old_value']): ?>
                                    <small><?php echo encode_output(substr($log['old_value'], 0, 50)); ?>...</small>
                                <?php else: ?>
                                    -
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($log['new_value']): ?>
                                    <small><?php echo encode_output(substr($log['new_value'], 0, 50)); ?>...</small>
                                <?php else: ?>
                                    -
                                <?php endif; ?>
                            </td>
                            <td><?php echo encode_output($log['created_at']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2>How Audit Logging Works</h2>
            <p>SQLite triggers automatically log all changes:</p>
            <pre>CREATE TRIGGER audit_comments_insert
AFTER INSERT ON comments
BEGIN
    INSERT INTO audit_log (table_name, record_id, action, user_id, new_value)
    VALUES ('comments', NEW.id, 'INSERT', NEW.user_id, NEW.content);
END;</pre>
        </div>

        <footer>
            <p>Web Security Demo - Algonquin College</p>
        </footer>
    </div>
</body>
</html>
