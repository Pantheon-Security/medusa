<?php
// MEDUSA benchmark corpus — crafted vulnerable PHP patterns (one+ per family).
// Locks in native php_security detection in the regression baseline.

// Injection
$res = $mysqli->query("SELECT * FROM users WHERE id = $id");
system("ping " . $_GET['host']);
$out = `ls $dir`;
eval($_POST['code']);
call_user_func($_GET['fn']);

// File access
include($_GET['page']);
$data = file_get_contents($_REQUEST['file']);
$obj = unserialize($_COOKIE['session']);
move_uploaded_file($tmp, $_FILES['f']['name']);

// Web
echo $_GET['name'];
curl_setopt($ch, CURLOPT_URL, $_GET['url']);
header($_GET['loc']);

// Crypto / secrets
$h = md5($password);
$t = mt_rand();
$api_key = "sk_live_realkey9876543210";
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
