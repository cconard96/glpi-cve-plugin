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

global $CFG_GLPI;
define('GLPI_ROOT', dirname(dirname(dirname(__DIR__))));
define("GLPI_CONFIG_DIR", GLPI_ROOT . "/tests");
include GLPI_ROOT . "/inc/includes.php";
include_once GLPI_ROOT . '/tests/GLPITestCase.php';
include_once GLPI_ROOT . '/tests/DbTestCase.php';
$plugin = new \Plugin();
$plugin->checkStates(true);
$plugin->getFromDBbyDir('cve');
if (!$plugin->checkGlpiVersion(['min' => PLUGIN_CVE_MIN_GLPI, 'max' => PLUGIN_CVE_MAX_GLPI])) {
  echo "\nPrerequisites are not met!";
  die(1);
}
if (!$plugin->isInstalled('cve')) {
  $plugin->install($plugin->getID());
}
if (!$plugin->isActivated('cve')) {
  $plugin->activate($plugin->getID());
}
