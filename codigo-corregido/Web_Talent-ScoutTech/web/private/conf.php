<?php

$db = new SQLite3(dirname(__FILE__) . "/database.db", SQLITE3_OPEN_READWRITE) or die ("Unable to open database");

$db->exec('PRAGMA foreign_keys = ON');
?>
