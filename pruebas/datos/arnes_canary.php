<?php
// Arnes de pruebas: carga las funciones del canary sin ejecutarlo y llama a una.
// Uso: php arnes_canary.php <funcion> '<argumentos en JSON>'
define('NX_CANARY_SOLO_FUNCIONES', true);
require __DIR__ . '/../../servidor/nx-canary.php';

$args = json_decode($argv[2] ?? '[]', true);
echo json_encode(call_user_func_array($argv[1], $args));
