<?php
require_once dirname(__FILE__) . '/conf.php';

$userId = FALSE;

function areUserAndPasswordValid($user, $password) {
    global $db, $userId;

    $stmt = $db->prepare('SELECT userId, password FROM users WHERE username = :username');
    $stmt->bindValue(':username', $user, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray();

    if (!$row || !isset($row['password'])) return FALSE;

    if (password_verify($password, $row['password'])) {
        $userId = $row['userId'];
        $_SESSION['userId'] = $userId;
        return TRUE;
    }
    return FALSE;
}

if (isset($_POST['username'])) {        
    $_SESSION['user'] = $_POST['username'];
    if (isset($_POST['password'])) {
        $_SESSION['password'] = $_POST['password'];
    } else {
        $_SESSION['password'] = "";
    }
} else {
    if (!isset($_POST['Logout']) && !isset($_SESSION['user'])) {
        $_SESSION['user'] = "";
        $_SESSION['password'] = "";
    }
}

if (isset($_POST['Logout'])) {
    session_unset();
    session_destroy();
    header("Location: index.php");
}

if (isset($_SESSION['user']) && isset($_SESSION['password'])) {
    if (areUserAndPasswordValid($_SESSION['user'], $_SESSION['password'])) {
        $login_ok = TRUE;
        $error = "";
    } else {
        $login_ok = FALSE;
        $error = "Invalid user or password.<br>";
    }
} else {
    $login_ok = FALSE;
    $error = "This page requires you to be logged in.<br>";
}

if ($login_ok == FALSE) {
?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Authentication page</title>
    </head>
    <body>
    <header class="auth">
        <h1>Authentication page</h1>
    </header>
    <section class="auth">
        <div class="message">
            <?= $error ?>
        </div>
        <section>
            <div>
                <h2>Login</h2>
                <form action="#" method="post">
                    <label>User</label>
                    <input type="text" name="username" required><br>
                    <label>Password</label>
                    <input type="password" name="password" required><br>
                    <input type="submit" value="Login">
                </form>
            </div>

            <div>
                <h2>Logout</h2>
                <form action="#" method="post">
                    <input type="submit" name="Logout" value="Logout">
            </div>
        </section>
    </section>
    <footer>
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
    </body>
    </html>
<?php
    exit(0);
}
?>