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

function plugin_cve_install()
{
	$migration = new PluginCveMigration(PLUGIN_CVE_VERSION);
	$migration->applyMigrations();
	return true;
}

function plugin_cve_uninstall()
{
	return true;
}

function plugin_cve_dashboardCards()
{
   $cards = [];
   $cards = array_merge($cards, PluginCveCve::dashboardCards());
   return $cards;
}
