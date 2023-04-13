<?php
/**
 * SimpleTOTP Authenticate script
 *
 * This script displays a page to the user, which requests that they
 * submit the response from their TOTP generator.
 *
 * @package simpleSAMLphp
 */

use SimpleSAML\Configuration;
use SimpleSAML\Utils;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\State;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;
use SimpleSAML\Logger;

$globalConfig = Configuration::getInstance();

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SimpleSAML_Error_BadRequest(
        'Missing required StateId query parameter.'
    );
}

$id = $_REQUEST['StateId'];

$sid = State::parseStateID($id);
if (!is_null($sid['url'])) {
	$httpUtils = new Utils\HTTP();
    $httpUtils->checkURLAllowed($sid['url']);
}

$state = State::loadState($id, 'simpletotp:request');
$displayed_error = NULL;

//if code is set, user has posted back to this page with a guess
if (array_key_exists('code', $_REQUEST)) {
    if (!ctype_digit($_REQUEST['code'])) {
        $displayed_error = "A valid TOTP token consists of only numeric values.";
    } else {

        //check if code is valid
        $code = getCode($state['mfa_secret']);
        Logger::debug("secret: " . $state['mfa_secret'] . " code entered: " .  $_REQUEST['code'] . " actual code: $code");

        if ($code === $_REQUEST['code']) {
            ProcessingChain::resumeProcessing($state);
        } else {
            $displayed_error = "You have entered the incorrect TOTP token.";
        }
    }
}

// populate values for template
$t = new Template($globalConfig, 'simpletotp:authenticate.twig');
$t->data['formData'] = array('StateId' => $id);
$t->data['formPost'] = Module::getModuleURL('simpletotp/authenticate.php');
$t->data['userError'] = $displayed_error;
echo $t->getContents();

#######################################
# Google Authentication functions below taken from 
# https://github.com/PHPGangsta/GoogleAuthenticator
# Copyright (c) 2012, Michael Kliewe All rights reserved.
#####################################
#TODO better way to include functions

function getCode($secret, $timeSlice = null) {
    if ($timeSlice === null) {
        $timeSlice = floor(time() / 30);
    }
    $secretkey = _base32Decode($secret);
    // Pack time into binary string
    $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
    // Hash it with users secret key
    $hm = hash_hmac('SHA1', $time, $secretkey, true);
    // Use last nipple of result as index/offset
    $offset = ord(substr($hm, -1)) & 0x0F;
    // grab 4 bytes of the result
    $hashpart = substr($hm, $offset, 4);
    // Unpak binary value
    $value = unpack('N', $hashpart);
    $value = $value[1];
    // Only 32 bits
    $value = $value & 0x7FFFFFFF;
    $modulo = pow(10, 6);
    return str_pad($value % $modulo, 6, '0', STR_PAD_LEFT);
}

function _base32Decode($secret) {
        if (empty($secret)) return '';
        $base32chars = _getBase32LookupTable();
        $base32charsFlipped = array_flip($base32chars);
        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues)) return false;
        for ($i = 0; $i < 4; $i++){
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) return false;
        }
        $secret = str_replace('=','', $secret);
        $secret = str_split($secret);
        $binaryString = "";
        for ($i = 0; $i < count($secret); $i = $i+8) {
            $x = "";
            if (!in_array($secret[$i], $base32chars)) return false;
            for ($j = 0; $j < 8; $j++) {
                $x .= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            for ($z = 0; $z < count($eightBits); $z++) {
                $binaryString .= ( ($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48 ) ? $y:"";
            }
        }
        return $binaryString;
    }
    function _getBase32LookupTable()
    {
        return array(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '='  // padding char
        );
    } 
