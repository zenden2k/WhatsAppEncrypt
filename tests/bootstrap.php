<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

error_reporting(E_ALL);
ini_set('display_errors', '1');

date_default_timezone_set('UTC');

const SAMPLES_DIR = __DIR__ . "/../resources/samples/";