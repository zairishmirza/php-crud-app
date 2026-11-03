<?php
// functions.php - generic CRUD function + small helpers

/**
 * One function for all CRUD.
 *   crud($conn, "INSERT", "users", ["username"=>"ali", ...]);
 *   crud($conn, "SELECT", "users", [], ["user_id"=>1]);
 *   crud($conn, "UPDATE", "users", ["phone"=>"0300"], ["user_id"=>1]);
 *   crud($conn, "DELETE", "users", [], ["user_id"=>1]);
 * SELECT returns an array of rows. Others return insert_id + affected_rows.
 */
function crud($conn, $operation, $table, $data = [], $where = []) {

    // Whitelist: table and column names can't be bound as parameters
    $allowed = [
        "users" => ["user_id","full_name","username","email","password","phone",
                    "gender","profile_image","role","status"],
        "password_resets" => ["reset_id","user_id","reset_token","expires_at","is_used"],
        "login_logs" => ["log_id","user_id","login_time","ip_address","login_status"],
    ];

    $operation = strtoupper($operation);

    if (!isset($allowed[$table])) throw new Exception("Invalid table name");

    foreach (array_merge(array_keys($data), array_keys($where)) as $col) {
        if (!in_array($col, $allowed[$table], true)) throw new Exception("Invalid column: $col");
    }

    // WHERE clause (equality only, joined with AND)
    $conditions = []; $values = [];
    foreach ($where as $col => $val) { $conditions[] = "`$col` = ?"; $values[] = $val; }
    $whereSQL = $conditions ? " WHERE " . implode(" AND ", $conditions) : "";

    if ($operation === "INSERT") {
        if (!$data) throw new Exception("No data provided");
        $cols = implode(", ", array_map(fn($c) => "`$c`", array_keys($data)));
        $ph   = implode(", ", array_fill(0, count($data), "?"));
        $sql  = "INSERT INTO `$table` ($cols) VALUES ($ph)";
        $values = array_values($data);

    } elseif ($operation === "SELECT") {
        $sql = "SELECT * FROM `$table`" . $whereSQL;

    } elseif ($operation === "UPDATE") {
        if (!$data || !$where) throw new Exception("UPDATE requires data and conditions");
        $set = array_map(fn($c) => "`$c` = ?", array_keys($data));
        $sql = "UPDATE `$table` SET " . implode(", ", $set) . $whereSQL;
        $values = array_merge(array_values($data), $values);

    } elseif ($operation === "DELETE") {
        if (!$where) throw new Exception("DELETE requires a WHERE condition");
        $sql = "DELETE FROM `$table`" . $whereSQL;

    } else {
        throw new Exception("Invalid CRUD operation");
    }

    $stmt = $conn->prepare($sql);
    if ($values) $stmt->bind_param(str_repeat("s", count($values)), ...$values);
    $stmt->execute();

    if ($operation === "SELECT") {
        $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
        return $rows;
    }

    $res = ["insert_id" => $stmt->insert_id, "affected_rows" => $stmt->affected_rows];
    $stmt->close();
    return $res;
}

// ---------- helpers ----------
function e($v) { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }

function redirect($page, $extra = "") {
    header("Location: index.php?page=" . $page . $extra);
    exit;
}

function flash($msg, $type = "success") { $_SESSION["flash"] = [$msg, $type]; }

function isLoggedIn() { return !empty($_SESSION["user_id"]); }

function requireLogin() {
    if (!isLoggedIn()) { flash("Please log in first.", "error"); redirect("login"); }
}

function currentUser($conn) {
    if (!isLoggedIn()) return null;
    $rows = crud($conn, "SELECT", "users", [], ["user_id" => $_SESSION["user_id"]]);
    return $rows[0] ?? null;
}

function csrfToken() {
    if (empty($_SESSION["csrf"])) $_SESSION["csrf"] = bin2hex(random_bytes(32));
    return $_SESSION["csrf"];
}
function csrfField() { return '<input type="hidden" name="csrf" value="' . csrfToken() . '">'; }
function csrfCheck() {
    return isset($_POST["csrf"], $_SESSION["csrf"]) && hash_equals($_SESSION["csrf"], $_POST["csrf"]);
}

function logLogin($conn, $userId, $status) {
    crud($conn, "INSERT", "login_logs", [
        "user_id" => $userId,
        "ip_address" => $_SERVER["REMOTE_ADDR"] ?? "",
        "login_status" => $status,
    ]);
}
