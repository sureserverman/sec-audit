<?php
// Intentionally insecure WordPress theme code — fixture for the php lane.

add_action( 'init', 'vuln_handler' );

function vuln_handler() {
    // Unescaped output of raw request input (XSS).
    echo $_GET['q'];

    // Form processed without nonce verification (CSRF).
    if ( isset( $_POST['name'] ) ) {
        update_option( 'display_name', $_POST['name'] );
    }

    // Unprepared SQL built from request input (SQLi).
    global $wpdb;
    $id = $_GET['id'];
    $wpdb->query( "SELECT * FROM users WHERE id = " . $id );
}
