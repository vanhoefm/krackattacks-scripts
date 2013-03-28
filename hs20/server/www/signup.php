<html>
<head>
<title>Hotspot 2.0 signup</title>
</head>
<body>

<?php

$id = $_GET["session_id"];

require('config.php');

$db = new PDO($osu_db);
if (!$db) {
   die($sqliteerror);
}

$row = $db->query("SELECT realm FROM sessions WHERE id='$id'")->fetch();
if ($row == false) {
   die("Session not found");
}
$realm = $row['realm'];

echo "<h3>Sign up for a subscription - $realm</h3>\n";

$row = $db->query("SELECT value FROM osu_config WHERE realm='$realm' AND field='free_account'")->fetch();
if ($row && strlen($row['value']) > 0) {
  echo "<p><a href=\"free.php?session_id=$id\">Sign up for free access</a></p>\n";
}

echo "<form action=\"add-mo.php\" method=\"POST\">\n";
echo "<input type=\"hidden\" name=\"id\" value=\"$id\">\n";
?>
Select a username and password. Leave password empty to get automatically
generated and machine managed password.<br>
Username: <input type="text" name="user"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Complete subscription registration">
</form>

<?php
echo "<p><a href=\"cert-enroll.php?id=$id\">Enroll a client certificate</a></p>\n"
?>

</body>
</html>
