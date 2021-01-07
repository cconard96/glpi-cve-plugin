<?php
/*
 -------------------------------------------------------------------------
 CVE
 Copyright (C) 2020-2021 by Curtis Conard
 https://github.com/cconard96/glpi-cve-plugin
 -------------------------------------------------------------------------
 LICENSE
 This file is part of CVE.
 CVE is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 CVE is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with CVE. If not, see <http://www.gnu.org/licenses/>.
 --------------------------------------------------------------------------
*/

/**
 * A CVE-Search API client
 */
class PluginCveApi {

   /**
    * Fetch a JSON response from a CVE-Search API GET endpoint.
    * @param string $endpoint The API endpoint including parameters such as '/cvefor/{cpe}' where '{cpe}' is the cpe code being used.
    * @param array $headers Array of headers to send to the API endpoint. Only used with the query endpoint currently. The headers should already be formatted as 'key: value'.
    * @return array The decoded JSON response or an empty array if nothing was received from the API but we also didn't get a 500 error.
    * @throws RuntimeException In the event of receiving a 500 return code.
    */
   private static function get(string $endpoint, array $headers = []): array
   {
      $config = PluginCveConfig::getConfig(true);
      if (empty($config['cve_url'])) {
         return [];
      }

      if (str_ends_with($config['cve_url'], '/')) {
         $config['cve_url'] = substr($config['cve_url'], 0, -1);
      }
      if (str_starts_with($endpoint, '/')) {
         $endpoint = substr($endpoint, 1);
      }

      $api_endpoint = $config['cve_url'] . '/api/' . $endpoint;

      $curl = curl_init($api_endpoint);

      curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
      curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
      if ($config['cve_ignore_cert']) {
         curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
         curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
      }
      $response = curl_exec($curl);
      $httpcode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
      curl_close($curl);

      if (!$response) {
         return [];
      }
      if ($httpcode === 500) {
         throw new RuntimeException(_x('error', 'Unknown CVE-Search API Error', 'cve'));
      }

      return json_decode($response, true);
   }
   /**
    * Forms a CPE 2.3 Code String which can be used to query the CVE-Search API.
    * @param string $cpe_part ('a': 'Application', 'o': 'Operating System', 'h': 'Hardware').
    * @param string $vendor The registered name of the vendor. This function will NOT attempt to format the vendor name.
    * @param string $product The registered name of the product. This function will NOT attempt to format the product name.
    * @param string $version The specific version of the product.
    * @param string $update The update level.
    * @param string $edition The edition.
    * @param string $language The language.
    * @return string The formed CPE 2.3 coded string.
    */
   public static function formCPE2_3String(string $cpe_part, string $vendor, string $product, string $version = '*', string $update = '*', string $edition = '*', string $language = '*'): string
   {
      return "cpe:2.3:$cpe_part:$vendor:$product:$version:$update:$edition:$language";
   }

   /**
    * @param $vendor
    * @return string
    */
   public static function formatVendorName($vendor): string
   {
      return strtolower(str_replace(' ', '_', $vendor));
   }

   /**
    * @param $product
    * @return string
    */
   public static function formatProductName($product): string
   {
      return strtolower(str_replace(' ', '_', $product));
   }

   /**
    * Retrieve a set of CVEs related to the provided CPE code
    * @param string $cpe CPE code
    * @param ?int $limit The maximum number of CVEs to return. If the limit is set, the CVE-Search API will sort results by the CVSS score.
    * @return array
    * @see PluginCveApi::formCPE2_3String()
    */
   public static function getCVEForCPE(string $cpe, int $limit = 50): array
   {
      $endpoint = "/cvefor/$cpe";
      if ($limit) {
         $endpoint .= "?limit=$limit";
      }
      return self::get($endpoint);
   }

   /**
    * Retrieve information about a single CVE
    * @param string $cve_id The CVE ID
    * @return array
    */
   public static function getCVE(string $cve_id): array
   {
      return self::get("/cve/$cve_id");
   }

   /**
    * Retrieves all Common Weakness Enumerations or information about a specific CWE if given a CWE ID
    * @var ?string $cwe_id
    * @return array
    */
   public static function getCWE(?string $cwe_id): array
   {
      $endpoint = "/cwe";
      if ($cwe_id) {
         $endpoint .= "/$cwe_id";
      }
      return self::get($endpoint);
   }

   /**
    * Retrieves all Common Attach Pattern Enumeration and Classification data related to a CWE
    * @param string $cweid
    * @return array
    */
   public static function getCAPECForCWE(string $cweid): array
   {
      return self::get("/capec/$cweid");
   }

   /**
    * Retrieves the Common Attach Pattern Enumeration and Classification data for the given CAPEC ID
    * @param string $capec_id
    * @return array
    */
   public static function getCAPEC(string $capec_id): array
   {
      return self::get("/capec/show/$capec_id");
   }

   /**
    * Retrieves the most recent $limit CVEs.
    * @var int $limit
    * @return array
    */
   public static function getRecentCVE(int $limit = 50): array
   {
      return self::get("/last?limit=$limit");
   }

   /**
    * Retrieve a list of CVEs based on certain filter criteria.
    * @param array $params CVE query filters. See below for recognized filters:<br>
    *    'rejected': Hide or show rejected CVEs (show (default), hide)<br>
    *    'cvss_score': CVSS score<br>
    *    'cvss_modifier': CVSS score match modifier (above, equals, below)<br>
    *    'time_start': Earliest time for a CVE (dd-mm-yyyy or dd-mm-yy format, using - or /)<br>
    *    'time_end': Latest time for a CVE (dd-mm-yyyy or dd-mm-yy format, using - or /)<br>
    *    'time_modifier': Timeframe for the CVEs, related to the start and end time (from, until, between, outside)<br>
    *    'time_type': The case-sensitive time property used in the criteria (Modified, Published, last-modified)<br>
    *    'skip': Skip the latest n CVEs<br>
    *    'limit': Limit the number of CVEs to return<br>
    * @return array
    */
   public static function query(array $params): array
   {
      $headers = [];
      $allowed_criteria = ['rejected', 'cvss_score', 'cvss_modifier', 'time_start', 'time_end', 'time_modifier', 'time_type', 'skip', 'limit'];
      $params = array_filter($params, static function($k, $v) use ($allowed_criteria) {
         return in_array($k, $allowed_criteria, true);
      });
      foreach ($params as $param => $value) {
         $headers[] = "$param: $value";
      }
      return self::get('/query', $headers);
   }

   /**
    * Retrieve a list of vendors
    * @return array
    */
   public static function getVendors(): array
   {
      $result = self::get('/browse');
      if (isset($result['vendor'])) {
         return $result['vendor'];
      }
      return $result;
   }

   /**
    * @param string $vendor
    * @return array
    */
   public static function getProductsByVendor(string $vendor): array
   {
      $vendor = self::formatVendorName($vendor);
      $result = self::get("/browse/$vendor");
      if (isset($result['product'])) {
         return $result['product'];
      }
      return $result;
   }

   /**
    * @param string $vendor
    * @param string $product
    * @return array
    */
   public static function getCVEByVendorAndProduct(string $vendor, string $product): array
   {
      $vendor = self::formatVendorName($vendor);
      $product = self::formatProductName($product);
      return self::get("/search/$vendor/$product");
   }

   /**
    * @param string $key
    * @param string $value
    * @return array
    */
   public static function getCVEByLink(string $key, string $value): array
   {
      return self::get("/link/$key/$value");
   }
}