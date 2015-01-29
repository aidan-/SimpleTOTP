<?php

/**
 * Template for error message users receive when they do not have a TOTP
 *  value when 2fa is enforced.
 */

$this->data['head']  = '<link rel="stylesheet" type="text/css" href="/' .
    $this->data['baseurlpath'] . 'module.php/simpletotp/style.css" />' . "\n";

$this->includeAtTemplateBase('includes/header.php');
?>

<h1>Two-Factor Authentication Required</h1>
<p>It seems you do not have two-factor authentication configured.  This 
system has been configured such that it is mandatory to use two-factor authentication.</p>
<p>If you are unsure what this means, or have your lost your two-factor authentication device, you
will need to contact your IT helpdesk for assistance.</p>

<?php
$this->includeAtTemplateBase('includes/footer.php');
