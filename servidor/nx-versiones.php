<?php
/**
 * Plugin Name: NexaSec - Ocultar versiones
 * Description: Quita las versiones de WordPress, plugins y tema del HTML publico. No es un control de
 *              seguridad: saca al sitio de los escaneres que eligen objetivos por version vulnerable.
 * Author: NexaSec
 *
 * Lo que NO puede ocultar: la version de jQuery/React que el propio JavaScript expone al navegador.
 * Los readme.txt de plugins se bloquean aparte, en el bloque "NexaSec Versiones" del .htaccess.
 */

defined( 'ABSPATH' ) || exit;

// 1) Generator de WordPress en <head>, feeds RSS y OPML.
remove_action( 'wp_head', 'wp_generator' );
add_filter( 'the_generator', '__return_empty_string' );

// 2) Comentario "optimized with the Yoast SEO plugin vX".
add_filter( 'wpseo_debug_markers', '__return_false' );

// 3) ?ver=4.2.4 -> ?ver=<hmac>. Se conserva el cache-busting: al actualizar un plugin cambia la
//    version y con ella el hash, pero desde fuera ya no se puede deducir cual es.
function nx_versiones_ocultar_ver( $src ) {
	if ( ! is_string( $src ) || false === strpos( $src, 'ver=' ) ) {
		return $src;
	}
	$host = wp_parse_url( $src, PHP_URL_HOST );
	if ( $host && wp_parse_url( home_url(), PHP_URL_HOST ) !== $host ) {
		return $src; // recursos de terceros: no se tocan
	}
	parse_str( (string) wp_parse_url( $src, PHP_URL_QUERY ), $args );
	if ( ! isset( $args['ver'] ) || '' === $args['ver'] ) {
		return $src;
	}
	$ruta = strtok( $src, '?' );
	$hash = substr( hash_hmac( 'sha256', $args['ver'] . '|' . $ruta, wp_salt( 'auth' ) ), 0, 10 );
	return add_query_arg( 'ver', $hash, $src );
}

// 4) Metas generator que plugins imprimen por su cuenta (Elementor, Redux). Se filtra el HTML final
//    en vez de desenganchar cada plugin: sobrevive a sus actualizaciones y a plugins nuevos.
function nx_versiones_limpiar_html( $html ) {
	if ( false === stripos( $html, '<html' ) ) {
		return $html;
	}
	return preg_replace( '#<meta\s+name=["\']generator["\'][^>]*>\s*#i', '', $html );
}

if ( ! is_admin() ) {
	add_filter( 'style_loader_src', 'nx_versiones_ocultar_ver', 9999 );
	add_filter( 'script_loader_src', 'nx_versiones_ocultar_ver', 9999 );

	add_action(
		'template_redirect',
		static function () {
			if ( is_feed() || wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
				return;
			}
			ob_start( 'nx_versiones_limpiar_html' );
		},
		0
	);
}
