<?php
// index.php - the whole app: routing, form handling, and views
require __DIR__ . "/db.php";
require __DIR__ . "/functions.php";

$public = ["login", "register", "forgot_password", "forgot_username", "reset_password"];
$page   = $_GET["page"] ?? (isLoggedIn() ? "dashboard" : "login");
$errors = [];
$notice = "";      // extra info shown on the page (e.g. reset link, recovered username)

// ---------- logout ----------
if ($page === "logout") {
    $_SESSION = [];
    session_destroy();
    session_start();
    flash("You have been logged out.");
    redirect("login");
}

// ---------- protect private pages ----------
$me = null;
if (!in_array($page, $public, true)) {
    requireLogin();
}
if (isLoggedIn()) {
    $me = currentUser($conn);
    if (!$me || $me["status"] !== "active") {   // deleted or deactivated meanwhile
        $_SESSION = []; session_destroy(); session_start();
        flash("Your account is not available.", "error");
        redirect("login");
    }
}
$isAdmin = $me && $me["role"] === "admin";

// ---------- handle POST (all form submissions) ----------
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!csrfCheck()) { http_response_code(419); die("Invalid CSRF token. Go back and reload the form."); }

    switch ($page) {

    // ===== REGISTER (INSERT) =====
    case "register":
        $full     = trim($_POST["full_name"] ?? "me");
        $username = trim($_POST["username"] ?? "guest");
        $email    = trim($_POST["email"] ?? "");
        $phone    = trim($_POST["phone"] ?? "");
        $gender   = $_POST["gender"] ?? "";
        $pass     = $_POST["password"] ?? "";
        $confirm  = $_POST["confirm"] ?? "";

        if ($full === "") $errors[] = "Full name is required.";
        if (!preg_match('/^[A-Za-z0-9_]{3,50}$/', $username)) $errors[] = "Username: 3-50 letters, numbers or underscore.";
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Enter a valid email.";
        if (strlen($pass) < 6) $errors[] = "Password must be at least 6 characters.";
        if ($pass !== $confirm) $errors[] = "Passwords do not match.";
        if (!in_array($gender, ["Male", "Female", "Other"], true)) $gender = null;

        if (!$errors) {
            if (crud($conn, "SELECT", "users", [], ["username" => $username])) $errors[] = "Username already taken.";
            if (crud($conn, "SELECT", "users", [], ["email" => $email]))       $errors[] = "Email already registered.";
        }
        if (!$errors) {
            // First registered user becomes admin, everyone else is a normal user
            $role = crud($conn, "SELECT", "users") ? "user" : "admin";
            crud($conn, "INSERT", "users", [
                "full_name" => $full, "username" => $username, "email" => $email,
                "password"  => password_hash($pass, PASSWORD_DEFAULT),
                "phone"     => $phone !== "" ? $phone : null,
                "gender"    => $gender, "role" => $role,
            ]);
            flash("Registration successful" . ($role === "admin" ? " (you are the admin)" : "") . ". Please log in.");
            redirect("login");
        }
        break;

    // ===== LOGIN (SELECT + session) =====
    case "login":
        $id   = trim($_POST["identifier"] ?? "");
        $pass = $_POST["password"] ?? "";

        $rows = crud($conn, "SELECT", "users", [], ["username" => $id]);
        if (!$rows) $rows = crud($conn, "SELECT", "users", [], ["email" => $id]);
        $user = $rows[0] ?? null;

        if ($user && $user["status"] === "active" && password_verify($pass, $user["password"])) {
            session_regenerate_id(true);
            $_SESSION["user_id"] = $user["user_id"];
            logLogin($conn, $user["user_id"], "success");
            redirect("dashboard");
        }
        if ($user) logLogin($conn, $user["user_id"], "failed");
        $errors[] = "Invalid username/email or password (or account inactive).";
        break;

    // ===== FORGOT USERNAME (SELECT by email) =====
    case "forgot_username":
        $email = trim($_POST["email"] ?? "");
        $rows  = crud($conn, "SELECT", "users", [], ["email" => $email]);
        // PRACTICE ONLY: real apps email the username instead of showing it on screen
        $notice = $rows ? "Your username is: <strong>" . e($rows[0]["username"]) . "</strong>"
                        : "No account found with that email.";
        break;

    // ===== FORGOT PASSWORD (INSERT token) =====
    case "forgot_password":
        $email = trim($_POST["email"] ?? "");
        $rows  = crud($conn, "SELECT", "users", [], ["email" => $email]);
        if ($rows) {
            $token = bin2hex(random_bytes(32));
            crud($conn, "INSERT", "password_resets", [
                "user_id"     => $rows[0]["user_id"],
                "reset_token" => hash("sha256", $token),      // only the hash is stored
                "expires_at"  => date("Y-m-d H:i:s", time() + 3600),
            ]);
            // PRACTICE ONLY: real apps email this link. We show it since localhost has no mail server.
            $notice = "Reset link (valid 1 hour): <a href='index.php?page=reset_password&token=$token'>Click here to reset</a>";
        } else {
            $notice = "If that email exists, a reset link has been created.";
        }
        break;

    // ===== RESET PASSWORD (UPDATE) =====
    case "reset_password":
        $token = $_POST["token"] ?? "";
        $pass  = $_POST["password"] ?? "";
        if (strlen($pass) < 6) $errors[] = "Password must be at least 6 characters.";
        if ($pass !== ($_POST["confirm"] ?? "")) $errors[] = "Passwords do not match.";

        $rows = crud($conn, "SELECT", "password_resets", [], ["reset_token" => hash("sha256", $token)]);
        $r = $rows[0] ?? null;
        if (!$r || $r["is_used"] || strtotime($r["expires_at"]) < time()) $errors[] = "Invalid or expired reset link.";

        if (!$errors) {
            crud($conn, "UPDATE", "users", ["password" => password_hash($pass, PASSWORD_DEFAULT)], ["user_id" => $r["user_id"]]);
            crud($conn, "UPDATE", "password_resets", ["is_used" => 1], ["reset_id" => $r["reset_id"]]);
            flash("Password updated. Please log in.");
            redirect("login");
        }
        break;

    // ===== EDIT USER (UPDATE) =====
    case "edit":
        $id = (int)($_POST["id"] ?? 0);
        if (!$isAdmin && $id !== (int)$me["user_id"]) { http_response_code(403); die("Not allowed."); }
        $rows = crud($conn, "SELECT", "users", [], ["user_id" => $id]);
        if (!$rows) { flash("User not found.", "error"); redirect("users"); }

        $full   = trim($_POST["full_name"] ?? "");
        $email  = trim($_POST["email"] ?? "");
        $phone  = trim($_POST["phone"] ?? "");
        $gender = $_POST["gender"] ?? "";
        $pass   = $_POST["password"] ?? "";
        if (!in_array($gender, ["Male", "Female", "Other"], true)) $gender = null;

        if ($full === "") $errors[] = "Full name is required.";
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Enter a valid email.";
        if ($pass !== "" && strlen($pass) < 6) $errors[] = "New password must be at least 6 characters.";
        if (!$errors) {
            $dup = crud($conn, "SELECT", "users", [], ["email" => $email]);
            if ($dup && (int)$dup[0]["user_id"] !== $id) $errors[] = "Email already used by another user.";
        }
        if (!$errors) {
            $data = ["full_name" => $full, "email" => $email, "phone" => $phone !== "" ? $phone : null, "gender" => $gender];
            if ($pass !== "") $data["password"] = password_hash($pass, PASSWORD_DEFAULT);
            if ($isAdmin && $id !== (int)$me["user_id"]) {      // admin can't lock themselves out
                if (in_array($_POST["role"] ?? "", ["admin", "user"], true))      $data["role"]   = $_POST["role"];
                if (in_array($_POST["status"] ?? "", ["active", "inactive"], true)) $data["status"] = $_POST["status"];
            }
            crud($conn, "UPDATE", "users", $data, ["user_id" => $id]);
            flash("User updated.");
            redirect($isAdmin ? "users" : "dashboard");
        }
        $_GET["id"] = $id;
        break;

    // ===== DELETE USER (DELETE) =====
    case "delete":
        $id = (int)($_POST["id"] ?? 0);
        if (!$isAdmin)               { http_response_code(403); die("Admins only."); }
        if ($id === (int)$me["user_id"]) { flash("You cannot delete yourself.", "error"); redirect("users"); }
        crud($conn, "DELETE", "users", [], ["user_id" => $id]);
        flash("User deleted.");
        redirect("users");
        break;
    }
}

// ---------- data needed by views ----------
$editUser = null;
if ($page === "edit") {
    $id = (int)($_GET["id"] ?? $me["user_id"]);
    if (!$isAdmin && $id !== (int)$me["user_id"]) { flash("Not allowed.", "error"); redirect("dashboard"); }
    $rows = crud($conn, "SELECT", "users", [], ["user_id" => $id]);
    $editUser = $rows[0] ?? null;
    if (!$editUser) { flash("User not found.", "error"); redirect("users"); }
}
$old = fn($k, $default = "") => e($_POST[$k] ?? $default);   // re-fill form after an error
$flash = $_SESSION["flash"] ?? null; unset($_SESSION["flash"]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CRUD App</title>
<style>
 *{box-sizing:border-box} body{font-family:system-ui,Arial,sans-serif;background:#f3f4f6;margin:0;color:#222}
 nav{background:#1f2937;padding:12px 24px;display:flex;gap:18px;align-items:center}
 nav a{color:#e5e7eb;text-decoration:none} nav a:hover{color:#fff} nav .brand{font-weight:700;color:#fff;margin-right:auto}
 .box{max-width:460px;margin:40px auto;background:#fff;padding:28px;border-radius:10px;box-shadow:0 2px 10px #0001}
 .wide{max-width:900px} h2{margin-top:0}
 label{display:block;margin:12px 0 4px;font-size:14px;font-weight:600}
 input,select{width:100%;padding:9px;border:1px solid #cbd5e1;border-radius:6px;font-size:15px}
 button,.btn{display:inline-block;background:#2563eb;color:#fff;border:0;padding:10px 16px;border-radius:6px;font-size:15px;cursor:pointer;text-decoration:none;margin-top:16px}
 button.danger{background:#dc2626;margin:0;padding:6px 10px;font-size:13px} .btn.small{padding:6px 10px;font-size:13px;margin:0}
 table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid #e5e7eb;text-align:left;font-size:14px}
 th{background:#f9fafb} .msg{padding:10px 14px;border-radius:6px;margin-bottom:14px}
 .success{background:#dcfce7;color:#166534} .error{background:#fee2e2;color:#991b1b} .info{background:#dbeafe;color:#1e40af;word-break:break-all}
 .links{margin-top:16px;font-size:14px} .links a{margin-right:12px}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0} .card{flex:1;min-width:150px;background:#f9fafb;padding:14px;border-radius:8px}
 .card b{font-size:26px;display:block}
</style>
</head>
<body>
<nav>
  <span class="brand">CRUD App</span>
  <?php if ($me): ?>
    <a href="index.php?page=dashboard">Dashboard</a>
    <a href="index.php?page=users">Users</a>
    <a href="index.php?page=edit&id=<?= (int)$me["user_id"] ?>">My Profile</a>
    <a href="index.php?page=logout">Logout (<?= e($me["username"]) ?>)</a>
  <?php else: ?>
    <a href="index.php?page=login">Login</a>
    <a href="index.php?page=register">Register</a>
  <?php endif; ?>
</nav>

<?php /* ================= VIEWS ================= */ ?>
<div class="box <?= in_array($page, ["users", "dashboard"]) ? "wide" : "" ?>">

<?php if ($flash): ?><div class="msg <?= e($flash[1]) ?>"><?= e($flash[0]) ?></div><?php endif; ?>
<?php foreach ($errors as $err): ?><div class="msg error"><?= e($err) ?></div><?php endforeach; ?>
<?php if ($notice): ?><div class="msg info"><?= $notice ?></div><?php endif; ?>

<?php if ($page === "register"): ?>
  <h2>Register</h2>
  <form method="post"><?= csrfField() ?>
    <label>Full name</label><input name="full_name" value="<?= $old("full_name") ?>" required>
    <label>Username</label><input name="username" value="<?= $old("username") ?>" required>
    <label>Email</label><input type="email" name="email" value="<?= $old("email") ?>" required>
    <label>Phone</label><input name="phone" value="<?= $old("phone") ?>">
    <label>Gender</label>
    <select name="gender"><option value="">-- select --</option>
      <?php foreach (["Male", "Female", "Other"] as $g): ?>
        <option <?= ($_POST["gender"] ?? "") === $g ? "selected" : "" ?>><?= $g ?></option>
      <?php endforeach; ?></select>
    <label>Password</label><input type="password" name="password" required>
    <label>Confirm password</label><input type="password" name="confirm" required>
    <button>Create account</button>
  </form>
  <div class="links"><a href="index.php?page=login">Already have an account?</a></div>

<?php elseif ($page === "login"): ?>
  <h2>Login</h2>
  <form method="post"><?= csrfField() ?>
    <label>Username or email</label><input name="identifier" value="<?= $old("identifier") ?>" required>
    <label>Password</label><input type="password" name="password" required>
    <button>Login</button>
  </form>
  <div class="links">
    <a href="index.php?page=register">Register</a>
    <a href="index.php?page=forgot_password">Forgot password?</a>
    <a href="index.php?page=forgot_username">Forgot username?</a>
  </div>

<?php elseif ($page === "forgot_username"): ?>
  <h2>Forgot username</h2>
  <form method="post"><?= csrfField() ?>
    <label>Your registered email</label><input type="email" name="email" required>
    <button>Find my username</button>
  </form>
  <div class="links"><a href="index.php?page=login">Back to login</a></div>

<?php elseif ($page === "forgot_password"): ?>
  <h2>Forgot password</h2>
  <form method="post"><?= csrfField() ?>
    <label>Your registered email</label><input type="email" name="email" required>
    <button>Create reset link</button>
  </form>
  <div class="links"><a href="index.php?page=login">Back to login</a></div>

<?php elseif ($page === "reset_password"): ?>
  <h2>Reset password</h2>
  <form method="post"><?= csrfField() ?>
    <input type="hidden" name="token" value="<?= e($_GET["token"] ?? $_POST["token"] ?? "") ?>">
    <label>New password</label><input type="password" name="password" required>
    <label>Confirm password</label><input type="password" name="confirm" required>
    <button>Update password</button>
  </form>

<?php elseif ($page === "dashboard"):
    $total  = count(crud($conn, "SELECT", "users"));
    $logs   = crud($conn, "SELECT", "login_logs", [], ["user_id" => $me["user_id"]]);
    $recent = array_slice(array_reverse($logs), 0, 5);
?>
  <h2>Welcome, <?= e($me["full_name"]) ?> 👋</h2>
  <div class="cards">
    <div class="card"><b><?= $total ?></b>Registered users</div>
    <div class="card"><b><?= count($logs) ?></b>Your login attempts</div>
    <div class="card"><b><?= e(ucfirst($me["role"])) ?></b>Your role</div>
  </div>
  <p>Username: <b><?= e($me["username"]) ?></b> &nbsp;|&nbsp; Email: <b><?= e($me["email"]) ?></b>
     &nbsp;|&nbsp; Member since: <b><?= e($me["created_at"]) ?></b></p>
  <h3>Your recent logins</h3>
  <table><tr><th>Time</th><th>IP</th><th>Status</th></tr>
  <?php foreach ($recent as $l): ?>
    <tr><td><?= e($l["login_time"]) ?></td><td><?= e($l["ip_address"]) ?></td><td><?= e($l["login_status"]) ?></td></tr>
  <?php endforeach; ?></table>

<?php elseif ($page === "users"):
    $users = crud($conn, "SELECT", "users");
?>
  <h2>Users (<?= count($users) ?>)</h2>
  <table>
    <tr><th>ID</th><th>Name</th><th>Username</th><th>Email</th><th>Phone</th><th>Role</th><th>Status</th><?php if ($isAdmin): ?><th>Actions</th><?php endif; ?></tr>
    <?php foreach ($users as $u): ?>
    <tr>
      <td><?= (int)$u["user_id"] ?></td><td><?= e($u["full_name"]) ?></td><td><?= e($u["username"]) ?></td>
      <td><?= e($u["email"]) ?></td><td><?= e($u["phone"]) ?></td><td><?= e($u["role"]) ?></td><td><?= e($u["status"]) ?></td>
      <?php if ($isAdmin): ?>
      <td style="white-space:nowrap">
        <a class="btn small" href="index.php?page=edit&id=<?= (int)$u["user_id"] ?>">Edit</a>
        <?php if ((int)$u["user_id"] !== (int)$me["user_id"]): ?>
        <form method="post" action="index.php?page=delete" style="display:inline" onsubmit="return confirm('Delete this user?')">
          <?= csrfField() ?><input type="hidden" name="id" value="<?= (int)$u["user_id"] ?>">
          <button class="danger">Delete</button>
        </form>
        <?php endif; ?>
      </td>
      <?php endif; ?>
    </tr>
    <?php endforeach; ?>
  </table>

<?php elseif ($page === "edit"): $isSelf = (int)$editUser["user_id"] === (int)$me["user_id"]; ?>
  <h2>Edit <?= $isSelf ? "my profile" : "user #" . (int)$editUser["user_id"] ?></h2>
  <form method="post" action="index.php?page=edit"><?= csrfField() ?>
    <input type="hidden" name="id" value="<?= (int)$editUser["user_id"] ?>">
    <label>Full name</label><input name="full_name" value="<?= $old("full_name", $editUser["full_name"]) ?>" required>
    <label>Username (cannot be changed)</label><input value="<?= e($editUser["username"]) ?>" disabled>
    <label>Email</label><input type="email" name="email" value="<?= $old("email", $editUser["email"]) ?>" required>
    <label>Phone</label><input name="phone" value="<?= $old("phone", $editUser["phone"]) ?>">
    <label>Gender</label>
    <select name="gender"><option value="">-- select --</option>
      <?php foreach (["Male", "Female", "Other"] as $g): ?>
        <option <?= ($_POST["gender"] ?? $editUser["gender"]) === $g ? "selected" : "" ?>><?= $g ?></option>
      <?php endforeach; ?></select>
    <?php if ($isAdmin && !$isSelf): ?>
      <label>Role</label>
      <select name="role"><?php foreach (["user", "admin"] as $r): ?><option <?= $editUser["role"] === $r ? "selected" : "" ?>><?= $r ?></option><?php endforeach; ?></select>
      <label>Status</label>
      <select name="status"><?php foreach (["active", "inactive"] as $s): ?><option <?= $editUser["status"] === $s ? "selected" : "" ?>><?= $s ?></option><?php endforeach; ?></select>
    <?php endif; ?>
    <label>New password (leave blank to keep current)</label><input type="password" name="password">
    <button>Save changes</button>
  </form>

<?php else: ?>
  <h2>Page not found</h2><a href="index.php">Go home</a>
<?php endif; ?>

</div>
</body>
</html>
