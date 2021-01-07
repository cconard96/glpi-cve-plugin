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

class PluginCveConfig extends CommonGLPI {
   static protected $notable = true;

   public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
   {
      if (!$withtemplate && $item->getType() === 'Config') {
         return PluginCveCve::getTypeName(Session::getPluralNumber());
      }
      return '';
   }

   public function showForm()
   {
      if (!Session::haveRight('config', UPDATE)) {
         return false;
      }
      $config = self::getConfig(true);

      echo "<form name='form' action=\"".Toolbox::getItemTypeFormURL('Config')."\" method='post'>";
      echo "<div class='center' id='tabsbody'>";
      echo "<table class='tab_cadre_fixe'><thead>";
      echo "<th colspan='4'>" . __('CVE-Search Settings', 'cve') . '</th></thead>';
      echo '<tr><td>';
      echo "<input type='hidden' name='config_class' value='".__CLASS__."'>";
      echo "<input type='hidden' name='config_context' value='plugin:cve'>";
      echo __('CVE Search URL') . '</td>';
      echo '<td>';
      echo Html::input('cve_url', ['value' => $config['cve_url'] ?? '']);
      echo '</td><td>' .__('CVE Search Ignore Certificate', 'cve'). '</td><td>';
      Dropdown::showYesNo('cve_ignore_cert', $config['cve_ignore_cert'] ?? 0);
      echo '</td></tr>';
      echo '</table>';

      echo "<table class='tab_cadre_fixe'>";
      echo "<tr class='tab_bg_2'>";
      echo "<td colspan='4' class='center'>";
      echo "<input type='submit' name='update' class='submit' value=\""._sx('button', 'Save'). '">';
      echo '</td></tr>';
      echo '</table>';
      echo '</div>';
      Html::closeForm();
   }

   public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
   {
      if ($item->getType() === 'Config') {
         $config = new self();
         $config->showForm();
      }
   }

   public static function undiscloseConfigValue($fields)
   {
      $to_hide = [];
      foreach ($to_hide as $f) {
         if (in_array($f, $fields, true)) {
            unset($fields[$f]);
         }
      }
      return $fields;
   }

   public static function getConfig(bool $force_all = false) : array
   {
      static $config = null;
      if ($config === null) {
         $config = Config::getConfigurationValues('plugin:cve');
      }
      if (!$force_all) {
         return self::undiscloseConfigValue($config);
      }

      return $config;
   }
}