<?php
/**
 * Author: afon
 */
if (!defined('PASS_ALGO')) { /* define PASS_ALGO in your project: 'sha256' 'sha512' ... */
    define('PASS_ALGO', 'sha256');
}

function pass_hash($password, $length = 32, $iterations = 10000, $salt_length = 20) {
    $salt = rand_str($salt_length);
    $h = base64_encode(hash_pbkdf2(PASS_ALGO, $password, $salt, $iterations, $length, true));
    return sprintf('$%02d$%02d$%s%s', $iterations/1000, $length, $salt, $h);
}

function pass_verify($password, $hash) {
    $params = explode('$', substr($hash, 1));
    $hash_len = ceil($params[1]/3) * 4;
    $salt_hash = array_pop($params);
    $params[] = substr($salt_hash, 0, strlen($salt_hash) - $hash_len);
    $params[] = substr($salt_hash, -$hash_len);
    if (base64_encode(hash_pbkdf2(PASS_ALGO, $password, $params[2], $params[0] * 1000, $params[1], true)) == $params[3]) {
        return true;
    } else {
        return false;
    }
}

function rand_str($length) {
    $s = 'abcdefghijklmnokprstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $ret = '';
    $count = strlen($s);
    for ($i=0; $i<$length; $i++) {
        $ret .= $s[mt_rand(0,$count - 1)];
    }
    return $ret;
}