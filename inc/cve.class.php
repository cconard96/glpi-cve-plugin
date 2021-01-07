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

class PluginCveCve extends CommonGLPI {

   public static function getTypeName($nb = 0)
   {
      return _n('CVE', 'CVEs', $nb, 'cve');
   }

   public static function getMenuName()
   {
      return self::getTypeName(Session::getPluralNumber());
   }

   public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
   {
      return self::createTabEntry(self::getTypeName(2));
   }

   public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
   {
      if ($item::getType() === Software::class) {
         return self::showForSoftware($item);
      }
      if ($item::getType() === SoftwareVersion::class) {
         return self::showForSoftwareVersion($item);
      }
      return false;
   }

   public static function getIcon() {
      return 'fas fa-shield-alt';
   }

   /**
    * Check if can view item
    *
    * @return boolean
    */
   static function canView() {
      return Config::canView();
   }

   private static function getAllSoftware(bool $include_glpi = false)
   {
      global $DB;

      $software_table = Software::getTable();
      $softwareversion_table = SoftwareVersion::getTable();
      $manufacturer_table = Manufacturer::getTable();

      $software_versions = $DB->request([
         'SELECT'    => [
            'glpi_softwares.name AS product',
            'glpi_softwareversions.name AS version',
            'glpi_manufacturers.name AS vendor'
         ],
         'FROM'      => $softwareversion_table,
         'LEFT JOIN' => [
            $software_table => [
               'FKEY'   => [
                  $softwareversion_table  => 'softwares_id',
                  $software_table         => 'id'
               ]
            ],
            $manufacturer_table => [
               'FKEY'   => [
                  $software_table      => 'manufacturers_id',
                  $manufacturer_table  => 'id'
               ]
            ]
         ]
      ]);

      $results = [];
      while ($data = $software_versions->next()) {
         $results[] = $data;
      }
      if ($include_glpi) {
         $results[] = [
            'software'  => 'GLPI',
            'vendor' => 'GLPI-Project',
            'version'   => GLPI_VERSION
         ];
      }
      return $results;
   }

   private static function formatCVEResults($results, $vendor = null, $product = null)
   {
      $formatted = [];
      foreach ($results as $cve) {
         if (!is_array($cve)) {
            return [];
         }
         $result = [
            'date_mod'        => $cve['Modified'],
            'date_published'  => $cve['Published'],
            'vendor'          => $vendor,
            'product'         => $product,
            'access'          => $cve['access'],
            'assigner'        => $cve['assigner'],
            'cvss'            => $cve['cvss'],
            'cvss-time'       => $cve['cvss-time'],
            'cvss-vector'     => $cve['cvss-vector'],
            'cwe'             => $cve['cwe'],
            'id'              => $cve['id'],
            'impact'          => $cve['impact'],
            'summary'         => htmlentities($cve['summary']),
            'references'      => $cve['references'],
            'vulnerable_configs' => []
         ];
         $vulnerable_configs = $cve['vulnerable_configuration'];
         foreach ($vulnerable_configs as $vulnerable_config) {
            if (is_array($vulnerable_config)) {
               $vulnerable_config = $vulnerable_config['id'];
            }
            list($cpe_name, $cpe_version, $cpe_part, $svendor, $sproduct, $sversion, $stability, $platform) = explode(':', $vulnerable_config);
            if ($result['vendor'] === null) {
               $result['vendor'] = $svendor;
            }
            if ($result['product'] === null) {
               $result['product'] = $sproduct;
            }
            $result['vulnerable_configs'][] = [
               'cpe_name'     => $cpe_name,
               'cpe_version'  => $cpe_version,
               'vendor'       => $svendor,
               'product'      => $sproduct,
               'version'      => $sversion,
               'stability'    => $stability,
               'platform'     => $platform
            ];
         }
         $formatted[] = $result;
      }
      return $formatted;
   }

   public static function getCVSSBackgroundColor(float $cvss_score): string
   {
      if ($cvss_score === 0) {
         return 'transparent';
      }

      if ($cvss_score > 0 && $cvss_score < 4) {
         return 'lightblue';
      }

      if ($cvss_score >= 4 && $cvss_score < 7) {
         return 'yellow';
      }

      if ($cvss_score >= 7 && $cvss_score < 9) {
         return 'orange';
      }

      if ($cvss_score >= 9) {
         return 'red';
      }
      return 'red';
   }

   /**
    * @param array $results
    * @return string
    */
   public static function getCVETable(array $results): string
   {
      $number = count($results);
      $start = 0;
      $out = '';
      $out .= "<div class='spaced'>";
      if ($number) {
         $out .= Html::printAjaxPager('', $start, $number, '', false);

         $out .= "<table class='tab_cadre_fixe'>";
         $out .= "<tr>";
         $out .= "<th>".__('CVE ID', 'cve')."</th>";
         $out .= "<th>".__('Date Published', 'cve')."</th>";
         $out .= "<th>".__('Date Modified', 'cve')."</th>";
         $out .= "<th>".__('Publisher', 'cve')."</th>";
         $out .= "<th>".__('Product', 'cve')."</th>";
         $out .= "<th>".__('Summary', 'cve')."</th>";
         $out .= "<th>".__('CVSS', 'cve')."</th>";
         $out .= "</tr>";

         foreach ($results as $result) {
            $out .= '<tr class="tab_bg_1">';
            $out .= "<td>{$result['id']}</td>";
            $out .= "<td>{$result['date_published']}</td>";
            $out .= "<td>{$result['date_mod']}</td>";
            $out .= "<td>{$result['vendor']}</td>";
            $out .= "<td>{$result['product']}</td>";
            $out .= "<td>{$result['summary']}</td>";
            $cvss = (float) $result['cvss'];
            $cvss_color = self::getCVSSBackgroundColor($cvss);
            $out .= "<td class='center' style='background-color: {$cvss_color}; color: black; font-weight: bold; font-size: 1.2em'>{$cvss}</td>";
            $out .= '</tr>';
         }
         $out .= '</table>';
      } else {
         $out .= "<p class='center b'>".__('No item found')."</p>";
      }
      $out .= "</div>";

      return $out;
   }

   public static function showCVEs()
   {
      $software_data = self::getAllSoftware(true);
      $results = [];

      foreach ($software_data as $data) {
         if (empty($data['vendor'])) {
            continue;
         }
         $cves = PluginCveApi::getCVEByVendorAndProduct($data['vendor'], $data['product']);
         if (!count($cves) || empty($cves['results']) || !is_array($cves['results'])) {
            continue;
         }
         $results = array_merge($results, self::formatCVEResults($cves['results'], $data['vendor'], $data['product']));
      }

      usort($results, static function($result1, $result2){
         $publish_1 = strtotime($result1['date_published']);
         $publish_2 = strtotime($result2['date_published']);
         if ($publish_1 < $publish_2) {
            return -1;
         } else if ($publish_1 > $publish_2) {
            return 1;
         } else {
            return 0;
         }
      });
      $results = array_reverse($results);

      echo self::getCVETable($results);
   }

   public static function showForSoftware(CommonGLPI $item)
   {
      global $DB;

      $software_table = Software::getTable();
      $manufacturer_table = Manufacturer::getTable();

      $software_versions = $DB->request([
         'SELECT'    => [
            'glpi_softwares.name AS product',
            'glpi_manufacturers.name AS vendor'
         ],
         'FROM'      => $software_table,
         'LEFT JOIN' => [
            $manufacturer_table => [
               'FKEY'   => [
                  $software_table      => 'manufacturers_id',
                  $manufacturer_table  => 'id'
               ]
            ]
         ],
         'WHERE'  => [
            'glpi_softwares.id'  => $item->getID()
         ]
      ]);

      $data = $software_versions->next();
      $results = [];

      if (!empty($data['vendor'])) {
         $cpe_code = PluginCveApi::formCPE2_3String('a', PluginCveApi::formatVendorName($data['vendor']),
            PluginCveApi::formatProductName($data['product']));
         $cves = PluginCveApi::getCVEForCPE($cpe_code);
         if (count($cves)) {
            $results = self::formatCVEResults($cves, $data['vendor'], $data['product']);
         }
      }

      usort($results, static function($result1, $result2){
         $publish_1 = strtotime($result1['date_published']);
         $publish_2 = strtotime($result2['date_published']);
         if ($publish_1 < $publish_2) {
            return -1;
         } else if ($publish_1 > $publish_2) {
            return 1;
         } else {
            return 0;
         }
      });
      $results = array_reverse($results);

      echo self::getCVETable($results);
   }

   public static function showForSoftwareVersion(CommonGLPI $item)
   {
      global $DB;

      $software_table = Software::getTable();
      $softwareversion_table = SoftwareVersion::getTable();
      $manufacturer_table = Manufacturer::getTable();

      $software_versions = $DB->request([
         'SELECT'    => [
            'glpi_softwares.name AS product',
            'glpi_softwareversions.name AS version',
            'glpi_manufacturers.name AS vendor'
         ],
         'FROM'      => $softwareversion_table,
         'LEFT JOIN' => [
            $software_table => [
               'FKEY'   => [
                  $softwareversion_table  => 'softwares_id',
                  $software_table         => 'id'
               ]
            ],
            $manufacturer_table => [
               'FKEY'   => [
                  $software_table      => 'manufacturers_id',
                  $manufacturer_table  => 'id'
               ]
            ]
         ],
         'WHERE'  => [
            'glpi_softwareversions.id'  => $item->getID()
         ]
      ]);

      $data = $software_versions->next();
      $results = [];

      if (!empty($data['vendor'])) {
         $cpe_code = PluginCveApi::formCPE2_3String('a', PluginCveApi::formatVendorName($data['vendor']),
            PluginCveApi::formatProductName($data['product']), $data['version']);
         $cves = PluginCveApi::getCVEForCPE($cpe_code);
         if (count($cves)) {
            $results = self::formatCVEResults($cves, $data['vendor'], $data['product']);
         }
      }

      usort($results, static function($result1, $result2){
         $publish_1 = strtotime($result1['date_published']);
         $publish_2 = strtotime($result2['date_published']);
         if ($publish_1 < $publish_2) {
            return -1;
         } else if ($publish_1 > $publish_2) {
            return 1;
         } else {
            return 0;
         }
      });
      $results = array_reverse($results);

      echo self::getCVETable($results);
   }

   public static function dashboardCards()
   {
      $cards = [];


      $cards["plugin_cve_latest_all"] = [
         'widgettype'  => ['articleList'],
         'label'       => 'Latest CVEs',
         'provider'    => 'PluginCveCve::cardProvider',
      ];

      return $cards;
   }

   public static function cardProvider($name = '', array $params = [])
   {
      $recent = PluginCveApi::getRecentCVE(10);

      $card_data = [];
      foreach ($recent as $data) {
         $card_data[] = [
            'label'     => $data['id'],
            'content'   => $data['summary'],
            'date'      => $data['Published'],
            'author'    => '',
            'url'       => ''
         ];
      }
      return [
         'label' => 'Latest CVEs',
         'data'  => $card_data,
         'number' => 10,
         'url'    => '',
         'icon'   => ''
      ];
   }
}