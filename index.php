<?php
/**
 * Root Entrypoint Redirector
 * Hospital Patient Data Security and Tamper Detection
 */

$query = $_SERVER['QUERY_STRING'] ? '?' . $_SERVER['QUERY_STRING'] : '';
header('Location: public/index.php' . $query);
exit;
