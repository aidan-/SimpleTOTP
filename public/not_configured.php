<?php

use SimpleSAML\Configuration;
use SimpleSAML\XHTML\Template;

$globalConfig = Configuration::getInstance();
$t = new Template($globalConfig, 'simpletotp:not_configured.twig');
echo $t->getContents();
