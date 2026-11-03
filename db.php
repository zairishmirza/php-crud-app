<?php
// db.php - database connection + session start

$DB_HOST = "localhost";
$DB_USER = "root";     // XAMPP/WAMP default
$DB_PASS = "";         // XAMPP/WAMP default is empty
$DB_NAME = "crud_app";

date_default_timezone_set("Asia/Karachi");

// Make MySQLi throw exceptions on errors (easier to debug)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

try {
    $conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
    $conn->set_charset("utf8mb4");
} catch (Exception $e) {
    die("Database connection failed: " . htmlspecialchars($e->getMessage()));
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
