<?php
namespace FR3D\XmlDSigTest\Adapter;

include '../XmlDSig.php';
/*define("__ROOT__",dirname(__FILE__));
var_dump(__FILE__);
var_dump(__DIR__);*/

use FR3D\XmlDSig\Adapter\XmlseclibsAdapter;
use FR3D\XmlDSig\Adapter\AdapterInterface;
use DOMDocument;


//签名 验证签名
function signature(){
    $adapter = new XmlseclibsAdapter();
    //$adapter->setPrivateKey( keystr , AdapterInterface:RSA_SHA1);  //default
    $adapter->setPrivateKey(file_get_contents(__DIR__ . '/_files/privkey.pem'));
    $adapter->setPublicKey(file_get_contents(__DIR__ . '/_files/pubkey.pem'));

    $adapter->addTransform(AdapterInterface::ENVELOPED);

    //$adapter->setCanonicalMethod(AdapterInterface::XML_C14N); //default
    $adapter->setCanonicalMethod('http://www.w3.org/2001/10/xml-exc-c14n#');

    //$adapter->setDigestAlgorithm(AdapterInterface::SHA1); //default

    $data = new DOMDocument();
    $data->load(__DIR__ . '/Adapter/_files/basic-doc.xml');
    var_dump($data->saveXML());

    $adapter->sign($data);
    var_dump($data->saveXML());

    var_dump($adapter->verify($data));
}
signature();



$xmlSucc = '<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ID="jhangegdglapafgjncklnhgifojnhhibeohcgmie" IssueInstant="2016-03-04T11:21:34Z" Version="2.0"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>EEn5bYOpSUL1R1zzgZhz3ExUi9Y=</DigestValue></Reference></SignedInfo><SignatureValue>VR/tbJoWhPx5bIhc3Ukf558zbnf86yhnSYLWZGiKU1z/tgrF0+Uq40BiSI7M86ttgeixzQcW4OUN43U2esXI+Bnr5v9VKMKkpvjF98iYfWrbaLCrmjd3KOt9dC79E/AJlZawVvWJnsQ5ZtPCvuksBZNDzxG9nsGt1tApko201AM=</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>lW6BHOiSpXI+ku65jkAjfIqgQN8hWNNtuqWtVZ8/bMgNqS3uJiBTCbKjnuyXAYZPs0lIu7vjRfaZDw+p7ynFwudzHXVlb67solMCcI2xOo2epYfDcY3MQHQLelf38p66C7lLhC4Md7sLNHtVjFY0Nlr4YtmbsuyCuXFjK6OdnN0=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><Assertion ID="kmhjllmnjhjcjpagmidlkhenbcicdfjemhgjpdfp" IssueInstant="2003-04-17T00:46:02Z" Version="2.0"><Issuer>https://www.opensaml.org/IDP</Issuer><Subject><NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">ldongyun</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="NBTjDsji0pqEFJEiOTHstUecARpLnnhBoBlst5aU" NotOnOrAfter="2017-03-04T11:21:34Z" Recipient="http://10.86.235.166/saml.php" /></SubjectConfirmation></Subject><Conditions NotBefore="2003-04-17T00:46:02Z" NotOnOrAfter="2017-03-04T11:21:34Z"><AudienceRestriction><Audience>http://10.86.235.166/saml.php</Audience></AudienceRestriction></Conditions><AuthnStatement AuthnInstant="2016-03-04T11:21:34Z"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></samlp:Response>';
$xmlErr = '<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ID="jhangegdglapafgjncklnhgifojnhhibeohcgmie" IssueInstant="2016-03-04T11:21:34Z" Version="2.0"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>EEn5bYOpSUL1R1zzgZhz3ExUi9Y=</DigestValue></Reference></SignedInfo><SignatureValue>VR/tbJoWhPx5bIhc3Ukf558zbnf86yhnSYLWZGiKU1z/tgrF0+Uq40BiSI7M86ttgeixzQcW4OUN43U2esXI+Bnr5v9VKMKkpvjF98iYfWrbaLCrmjd3KOt9dC79E/AJlZawVvWJnsQ5ZtPCvuksBZNDzxG9nsGt1tApko201AM=</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>lW6BHOiSpXI+ku65jkAjfIqgQN8hWNNtuqWtVZ8/bMgNqS3uJiBTCbKjnuyXAYZPs0lIu7vjRfaZDw+p7ynFwudzHXVlb67solMCcI2xOo2epYfDcY3MQHQLelf38p66C7lLhC4Md7sLNHtVjFY0Nlr4YtmbsuyCuXFjK6OdnN0=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><Assertion ID="kmhjllmnjhjcjpagmidlkhenbcicdfjemhgjpdfp" IssueInstant="2003-04-17T00:46:02Z" Version="2.0"><Issuer>https://www.opensaml.org/IDP</Issuer><Subject><NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">ldongyun</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="NBTjDsji0pqEFJEiOTHstUecARpLnnhBoBlst5aU" NotOnOrAfter="2017-03-04T11:21:34Z" Recipient="http://10.86.235.166/saml.php" /></SubjectConfirmation></Subject><Conditions NotBefore="2003-04-17T00:46:02Z" NotOnOrAfter="2017-03-04T11:21:34Z"><AudienceRestriction><Audience>http://10.86.235.166/saml.php</Audience></AudienceRestriction></Conditions><AuthnStatement AuthnInstant="2016-03-04T11:21:34Z"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password1</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></samlp:Response>';

//验证xml签名
function verify($xmlstr,$pubKeyPath=null){
    $adapter = new XmlseclibsAdapter();
    if($pubKeyPath){
        $adapter->setPublicKey(file_get_contents($pubKeyPath));
    }
    $data = new DOMDocument();
    $data->loadXML($xmlstr);
    return $adapter->verify($data);
}

var_dump(verify($xmlSucc));
var_dump(verify($xmlErr));



/*
var_dump('-----------------');
$data1 = new DOMDocument();
$data1->load(__DIR__ . '/req.xml');
var_dump($data1);
print_r($data1);
var_dump($adapter->verify($data1));

var_dump('-----------------');
$data2 = new DOMDocument();
$data2->load(__DIR__ . '/req.xml');
var_dump($data2);
var_dump($adapter->verify($data2));*/



//include 'src/Soap/SoapClient.php';

/*$sc = new SoapClient(
    __DIR__ . '\req.xml',
    [
        'trace' => true,
        'exceptions' => false,
    ]
);*/


/*
$degist = 'EEn5bYOpSUL1R1zzgZhz3ExUi9Y=';
$SignedInfo = '<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>EEn5bYOpSUL1R1zzgZhz3ExUi9Y=</DigestValue></Reference></SignedInfo>';

$SignedInfoXML = new DOMDocument('1.0');
$SignedInfoXML->loadXML($SignedInfo);
$s =$SignedInfoXML->C14N(true,true);

$sign = 'VR/tbJoWhPx5bIhc3Ukf558zbnf86yhnSYLWZGiKU1z/tgrF0+Uq40BiSI7M86ttgeixzQcW4OUN43U2esXI+Bnr5v9VKMKkpvjF98iYfWrbaLCrmjd3KOt9dC79E/AJlZawVvWJnsQ5ZtPCvuksBZNDzxG9nsGt1tApko201AM=';

$public_key = file_get_contents("x509.pem");
$pkeyid = openssl_pkey_get_public($public_key);

$result='';*/

?>