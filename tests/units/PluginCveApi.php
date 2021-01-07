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

namespace tests\units;

class PluginCveApi extends \GLPITestCase {

   public function testFormCPE2_3StringProvider()
   {
      return [
         ['a', 'glpi-project', 'glpi', '9.4.0', '*', '*', '*', 'cpe:2.3:a:glpi-project:glpi:9.4.0:*:*:*']
      ];
   }

   /**
    * @dataProvider testFormCPE2_3StringProvider
    */
   public function testFormCPE2_3String($cpe_part, $vendor, $product, $version, $update, $edition, $language, $expected)
   {
      $cpe_code = \PluginCveApi::formCPE2_3String($cpe_part, $vendor, $product, $version, $update, $edition, $language);

      $this->string($cpe_code)->isEqualTo($expected);
   }

   public function testFormatVendorNameProvider()
   {
      return [
         ['GLPI-Project', 'glpi-project'],
         ['GLPI Project', 'glpi_project']
      ];
   }

   /**
    * @dataProvider testFormatVendorNameProvider
    */
   public function testFormatVendorName($original, $expected)
   {
      $formatted = \PluginCveApi::formatVendorName($original);

      $this->string($formatted)->isEqualTo($expected);
   }

   public function testFormatProductNameProvider()
   {
      return [
         ['GLPI', 'glpi'],
         ['Active Directory', 'active_directory'],
         ['ASP.NET Core', 'asp.net_core']
      ];
   }

   /**
    * @dataProvider testFormatProductNameProvider
    */
   public function testFormatProductName($original, $expected)
   {
      $formatted = \PluginCveApi::formatProductName($original);

      $this->string($formatted)->isEqualTo($expected);
   }
}