<?php
require __DIR__ . '/lib/xmlseclibs/xmlseclibs.php';

$xsrcdir = __DIR__ . '/src/';
require $xsrcdir . '/Adapter/AdapterInterface.php';
require $xsrcdir . '/Adapter/XmlseclibsAdapter.php';
require $xsrcdir . '/Soap/SoapClient.php';
?>