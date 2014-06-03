<?php
/**
 * Author: afon
 */
if (!defined('PASS_ALGO')) { /* define PASS_ALGO in your project: 'sh2a8' => 'sha256', 'sh2a9' => 'sha512' ... */
    define('PASS_ALGO', 'sh2a8');
}
define('DELI', '$');
$algo_map = ['sh2a8' => 'sha256', 'sh2a9' => 'sha512'];

function pass_hash($password, $length = 32, $iterations = 10000, $salt_length = 20) {
    global $algo_map;
    $salt = rand_str($salt_length);
    $h = base64_encode(hash_pbkdf2($algo_map[PASS_ALGO], $password, $salt, $iterations, $length, true));
    return sprintf('%s%s%02d%s%02d%s%s%s', PASS_ALGO, DELI, $iterations/1000, DELI, $length, DELI, $salt, $h);
}

function pass_verify($password, $hash) {
    global $algo_map;
    $params = explode(DELI, $hash);
    $hash_len = ceil($params[2]/3) * 4;
    $salt_hash = array_pop($params);
    $params[] = substr($salt_hash, 0, strlen($salt_hash) - $hash_len);
    $params[] = substr($salt_hash, -$hash_len);
    if (base64_encode(hash_pbkdf2($algo_map[$params[0]], $password, $params[3], $params[1] * 1000, $params[2], true)) == $params[4]) {
        return true;
    } else {
        return false;
    }
}

function rand_str($length) {
    $s = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $ret = '';
    $count = strlen($s);
    for ($i=0; $i<$length; $i++) {
        $ret .= $s[mt_rand(0,$count - 1)];
    }
    return $ret;
}