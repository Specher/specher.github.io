<?php 
require_once('aes.php');

$action = @$_GET['action'];
$str = trim(@$_POST['str']);
if (empty($str)) exit('内容不能为空！');
$key = 'MYgGnQE2jDFADSFFDSEWsdD2'; //密钥

$aes = new Aes($key);
if ($action == 'en') {
    $str = $aes->encrypt($str);
} else {
    $str = $aes->decrypt($str);
}
echo $str;
