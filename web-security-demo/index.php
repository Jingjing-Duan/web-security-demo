<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Web Security Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px auto;
            max-width: 900px;
            line-height: 1.6;
        }
        h1 {
            text-align: center;
        }
        .menu {
            margin: 20px 0;
            padding: 20px;
            background: #f3f3f3;
            border-radius: 6px;
        }
        .menu a {
            display: block;
            margin: 8px 0;
            font-size: 18px;
        }
        .section {
            margin: 25px 0;
            padding: 15px;
            border-left: 4px solid #888;
            background: #fafafa;
        }
        h2 { margin-top: 0; }
    </style>
</head>

<body>

<h1>SQL Injection, XSS & Secure Development Demo</h1>

<div class="menu">
    <h2>Project Demo Menu</h2>
    <a href="/vulnerable/index.php">🔓 Vulnerable Version</a>
    <a href="/secure/index.php">🔐 Secure Version</a>
</div>

<div class="section">
    <h2>Project Overview</h2>
    <p>
        This project demonstrates common web application vulnerabilities and how to fix them,
        using a PHP + SQLite login and comment system.  
        It includes two parallel versions:
    </p>
    <ul>
        <li><strong>Vulnerable Version (/vulnerable)</strong> – intentionally insecure</li>
        <li><strong>Secure Version (/secure)</strong> – properly protected with best practices</li>
    </ul>
</div>

<div class="section">
    <h2>Vulnerabilities Demonstrated</h2>
    <ol>
        <li><strong>SQL Injection (SQLi)</strong><br>
            Vulnerable: raw string concatenation<br>
            Secure: PDO prepared statements
        </li>

        <li><strong>Cross-Site Scripting (XSS)</strong><br>
            Vulnerable: outputting user input directly<br>
            Secure: <code>htmlspecialchars()</code> + sanitization
        </li>

        <li><strong>Password Management</strong><br>
            Vulnerable: storing plain-text passwords<br>
            Secure: <code>password_hash()</code> (Argon2ID/Bcrypt)
        </li>

        <li><strong>Session Security</strong><br>
            Vulnerable: no session regeneration, weak cookie settings<br>
            Secure: session_regenerate_id(), HttpOnly + Secure + SameSite flags
        </li>

        <li><strong>Database Security</strong><br>
            Vulnerable: DB stored in public webroot<br>
            Secure: DB outside webroot, restricted access, audit logs
        </li>

        <li><strong>Data Encryption</strong><br>
            Vulnerable: sensitive data stored in plain text<br>
            Secure: AES-256-GCM encryption for sensitive fields
        </li>
    </ol>
</div>

<div class="section">
    <h2>Authors</h2>
    <p>
        Fucun Zhou, Jingjing Duan, Jiaxin Fan, Yan Fei<br>
        Course: Web Security Basics (CST8265) – Algonquin College
    </p>
</div>

</body>
</html>
