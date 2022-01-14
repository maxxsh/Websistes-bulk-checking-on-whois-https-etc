<?php

//PHP domain whois script not return all information https://stackoverflow.com/questions/49803380/php-domain-whois-script-not-return-all-information
function GetWhoisInfo($whoisserver, $domain)
{
  $port = 43;
  $timeout = 5;
  // $fp = @fsockopen($whoisserver, $port, $errno, $errstr, $timeout) or die("Socket Error for ".$domain . $errno . " - " . $errstr);
  $fp = @fsockopen($whoisserver, $port, $errno, $errstr, $timeout);
  if (!$fp) {
    $out = array("whoisserverError" => $errstr);
    return $out;
  } else {
    stream_set_blocking($fp, true);
    fputs($fp, $domain . "\r\n");
    $out = "";
    while (!feof($fp)) {
      $out .= fgets($fp);
    }
    fclose($fp);
    return $out;
  }
}

function GetRegistrarWhoisServer($whoisserver, $domain)
{
  $out = GetWhoisInfo($whoisserver, $domain);
  $rws_string = explode("\r\n", $out);
  $rws = explode("Registrar WHOIS Server: ", $rws_string[2])[1];
  return $rws;
}

function WhoisToJson($winfo)
{
  $winfoarr = explode(PHP_EOL, $winfo);
  $jsonarr = [];
  foreach ($winfoarr as $info) {
    $infodata = explode(": ", $info);
    if ($infodata[0] !== "") $jsonarr[$infodata[0]] = $infodata[1];
    //avoid to process privacy info at the end of whois service output
    if ($infodata[0] === "DNSSEC") break;
  }
  return json_encode($jsonarr);
}
function WhoisToArray($winfo)
{
  $rows = explode("\n", $winfo);
  $arr = array('info' => "");
  foreach ($rows as $row) {
    $posOfFirstColon = strpos($row, ":");
    if ($posOfFirstColon === FALSE)
      $arr['info'] .= $row;
    else
      $arr[substr($row, 0, $posOfFirstColon)] = trim(substr($row, $posOfFirstColon + 1));
  }
  return $arr;
}

function QueryWhoisServer($whoisserver, $domain)
{
  //query to $whoisserver whois to get registrar whois server address only
  $rws = GetRegistrarWhoisServer($whoisserver, $domain);
  //query to registrar whois server (registrar whois servers are returning contact infos)
  $out = GetWhoisInfo($rws, $domain);
  if (!is_array($out)) {
    //parsing infos and formatting to json
    // return WhoisToJson($out);
    //parsing infos and formatting to Array
    return WhoisToArray($out);
  } else {
    //   $out = array("Registrar Abuse Contact Email" => $out['whoisserverError']);
    $out = array("Registrar Abuse Contact Email" => $out['whoisserverError']);
    return $out;
  }
}

function getDomain($url)
{
  preg_match('/(?P<domain>[a-z0-9][a-z0-9\-]{1,63}\.[a-z\.]{2,6})$/i', $url, $regs);
  return $regs['domain'];
}

// Adding a line on Google Sheets
require 'vendor-sheets/autoload.php'; // google-api-php-client path
function getClient()
{
  $client = new Google_Client();
  $client->setApplicationName('Project');
  $client->setScopes(Google_Service_Sheets::SPREADSHEETS);
  //PATH TO JSON FILE DOWNLOADED FROM GOOGLE CONSOLE FROM STEP 7
  $client->setAuthConfig('updated-sheets-reverence-website-54cb3fd61dc9.json');
  $client->setAccessType('offline');
  return $client;
}

// Get the API client and construct the service object.
$client = getClient();
$service = new Google_Service_Sheets($client);
$spreadsheetId = '1XLBA9Zhsfcouoxb65465R-XxsdWhD_ZsyR8mPL0PY';  // spreadsheet Id
$range = 'Financial Saskatoon!A2:A'; // Sheet name 
$response = $service->spreadsheets_values->get($spreadsheetId, $range);
$values = $response->getValues();

if (empty($values)) {
  print "No data found.\n";
} else {
  foreach ($values as $key => $url) {
    $hostname = trim(parse_url($url[0])[host]);
    $testurl = 'https://' . $hostname . trim(parse_url($url[0])[path]);
    $httpresponseheader = get_headers($testurl)[0];
    $num = $key + 2;
    $abuse_contact_email = QueryWhoisServer("whois.verisign-grs.com", getDomain($hostname))["Registrar Abuse Contact Email"];
    $dmarcrecored = dns_get_record('_dmarc.' . $hostname, DNS_TXT)[0][txt];
    $cellvalues = [
      [
        $httpresponseheader ? $httpresponseheader : false,
        $dmarcrecored ? $dmarcrecored : false,
        $abuse_contact_email ? $abuse_contact_email : false,
      ],
    ];

    $body = new Google_Service_Sheets_ValueRange([
      'values' => $cellvalues
    ]);

    $params = ["valueInputOption" => "RAW"];
    $result = $service->spreadsheets_values->update($spreadsheetId, 'Financial Saskatoon!B' . $num, $body, $params);
  }
}
