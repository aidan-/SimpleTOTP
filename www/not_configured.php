<?php

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'simpletotp:not_configured.php');
$t->show();
