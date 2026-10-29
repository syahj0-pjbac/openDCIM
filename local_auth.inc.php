<?php
/*
	local_auth.inc.php

	Pembantu (helper) untuk login lokal username/password di openDCIM.
	Dipakai oleh:
	  - login_ldap.php   (halaman login pengganti)
	  - local_users.php  (halaman kelola password)

	Yang dikerjakan file ini:
	  - membuat tabel fac_LocalAuth dan fac_LoginAttempts (otomatis, sekali)
	  - menyimpan password sebagai hash (password_hash / bcrypt), bukan teks biasa
	  - token CSRF untuk semua form
	  - pembatasan percobaan login (per username dan per alamat IP)
*/

if ( !function_exists( 'localauth_init' ) ) {

// Pengaturan -- ubah di sini bila perlu
define( 'LOCALAUTH_USER_MAX_FAILS', 5 );    // gagal login per username sebelum dikunci
define( 'LOCALAUTH_IP_MAX_FAILS', 20 );     // gagal login per alamat IP sebelum dikunci
define( 'LOCALAUTH_LOCK_SECONDS', 900 );    // lama kunci (detik) = 15 menit
define( 'LOCALAUTH_MIN_PASSWORD', 10 );     // panjang minimal password

// Escape HTML
function la_h( $s ) {
	return htmlspecialchars( (string)$s, ENT_QUOTES, 'UTF-8' );
}

// Buat tabel bila belum ada
function localauth_init() {
	global $dbh;
	static $done = false;
	if ( $done ) {
		return;
	}

	try {
		$dbh->exec( "CREATE TABLE IF NOT EXISTS fac_LocalAuth (
			UserID varchar(255) NOT NULL,
			PasswordHash varchar(255) NOT NULL,
			UpdatedAt datetime NOT NULL,
			PRIMARY KEY (UserID)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8" );

		$dbh->exec( "CREATE TABLE IF NOT EXISTS fac_LoginAttempts (
			AttemptKey varchar(64) NOT NULL,
			Attempts int NOT NULL DEFAULT 0,
			LastAttempt datetime NOT NULL,
			PRIMARY KEY (AttemptKey)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8" );
	} catch ( PDOException $e ) {
		error_log( 'local_auth: gagal membuat tabel: ' . $e->getMessage() );
		die( 'Gagal menyiapkan tabel login lokal. Periksa error_log dan hak akses database.' );
	}

	$done = true;
}

/* ---------- CSRF ---------- */

function localauth_csrf_token() {
	if ( empty( $_SESSION['la_csrf'] ) ) {
		$_SESSION['la_csrf'] = bin2hex( random_bytes( 32 ) );
	}
	return $_SESSION['la_csrf'];
}

function localauth_csrf_check( $token ) {
	return isset( $_SESSION['la_csrf'] ) && is_string( $token ) && hash_equals( $_SESSION['la_csrf'], $token );
}

/* ---------- Pembatasan percobaan login ---------- */

function localauth_key_user( $username ) {
	return 'u:' . sha1( strtolower( trim( (string)$username ) ) );
}

function localauth_key_ip() {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
	return 'ip:' . substr( $ip, 0, 45 );
}

function localauth_is_locked( $key, $max ) {
	global $dbh;
	$st = $dbh->prepare( "SELECT Attempts, TIMESTAMPDIFF(SECOND, LastAttempt, NOW()) AS Age
		FROM fac_LoginAttempts WHERE AttemptKey=:k" );
	$st->execute( array( ':k' => $key ) );
	$row = $st->fetch( PDO::FETCH_ASSOC );
	if ( !$row ) {
		return false;
	}
	if ( (int)$row['Age'] > LOCALAUTH_LOCK_SECONDS ) {
		return false;
	}
	return ( (int)$row['Attempts'] >= $max );
}

function localauth_record_failure( $key ) {
	global $dbh;
	$st = $dbh->prepare( "INSERT INTO fac_LoginAttempts (AttemptKey, Attempts, LastAttempt)
		VALUES (:k, 1, NOW())
		ON DUPLICATE KEY UPDATE
			Attempts = IF(TIMESTAMPDIFF(SECOND, LastAttempt, NOW()) > :w, 1, Attempts + 1),
			LastAttempt = NOW()" );
	$st->bindValue( ':k', $key, PDO::PARAM_STR );
	$st->bindValue( ':w', LOCALAUTH_LOCK_SECONDS, PDO::PARAM_INT );
	$st->execute();

	// Bersihkan catatan yang sudah lama
	$dbh->exec( "DELETE FROM fac_LoginAttempts WHERE LastAttempt < (NOW() - INTERVAL 1 DAY)" );
}

function localauth_clear( $key ) {
	global $dbh;
	$st = $dbh->prepare( "DELETE FROM fac_LoginAttempts WHERE AttemptKey=:k" );
	$st->execute( array( ':k' => $key ) );
}

/* ---------- User dan password ---------- */

// Cari user di tabel fac_People (tidak peka huruf besar/kecil, sama seperti openDCIM)
function localauth_find_person( $username ) {
	global $dbh;
	$st = $dbh->prepare( "SELECT PersonID, UserID, Disabled,
			(ExpirationDate IS NOT NULL AND ExpirationDate <> '0000-00-00' AND ExpirationDate < CURDATE()) AS Expired
		FROM fac_People WHERE UCASE(UserID)=UCASE(:u) LIMIT 1" );
	$st->execute( array( ':u' => $username ) );
	$row = $st->fetch( PDO::FETCH_ASSOC );
	return $row ? $row : false;
}

function localauth_has_password( $userid ) {
	global $dbh;
	$st = $dbh->prepare( "SELECT 1 FROM fac_LocalAuth WHERE UserID=:u" );
	$st->execute( array( ':u' => $userid ) );
	return (bool)$st->fetch( PDO::FETCH_NUM );
}

function localauth_set_password( $userid, $password ) {
	global $dbh;
	$hash = password_hash( $password, PASSWORD_DEFAULT );
	$st = $dbh->prepare( "INSERT INTO fac_LocalAuth (UserID, PasswordHash, UpdatedAt)
		VALUES (:u, :h, NOW())
		ON DUPLICATE KEY UPDATE PasswordHash=:h2, UpdatedAt=NOW()" );
	return $st->execute( array( ':u' => $userid, ':h' => $hash, ':h2' => $hash ) );
}

function localauth_remove_password( $userid ) {
	global $dbh;
	$st = $dbh->prepare( "DELETE FROM fac_LocalAuth WHERE UserID=:u" );
	return $st->execute( array( ':u' => $userid ) );
}

// Cek password. Bila user belum punya password, tetap memakan waktu yang sama
// supaya tidak bisa dipakai untuk menebak username.
function localauth_verify( $userid, $password ) {
	global $dbh;
	$st = $dbh->prepare( "SELECT PasswordHash FROM fac_LocalAuth WHERE UserID=:u" );
	$st->execute( array( ':u' => $userid ) );
	$row = $st->fetch( PDO::FETCH_ASSOC );

	if ( !$row ) {
		password_hash( $password, PASSWORD_DEFAULT );
		return false;
	}
	if ( !password_verify( $password, $row['PasswordHash'] ) ) {
		return false;
	}
	if ( password_needs_rehash( $row['PasswordHash'], PASSWORD_DEFAULT ) ) {
		localauth_set_password( $userid, $password );
	}
	return true;
}

// Kembalikan pesan kesalahan (string) bila password tidak memenuhi syarat, atau "" bila lolos
function localauth_password_error( $password, $userid ) {
	if ( strlen( $password ) < LOCALAUTH_MIN_PASSWORD ) {
		return 'Password minimal ' . LOCALAUTH_MIN_PASSWORD . ' karakter.';
	}
	if ( strlen( $password ) > 72 ) {
		return 'Password maksimal 72 karakter.';
	}
	if ( strcasecmp( $password, (string)$userid ) == 0 ) {
		return 'Password tidak boleh sama dengan username.';
	}

	$classes = 0;
	if ( preg_match( '/[a-z]/', $password ) )        { $classes++; }
	if ( preg_match( '/[A-Z]/', $password ) )        { $classes++; }
	if ( preg_match( '/[0-9]/', $password ) )        { $classes++; }
	if ( preg_match( '/[^A-Za-z0-9]/', $password ) ) { $classes++; }
	if ( $classes < 2 ) {
		return 'Password harus memuat minimal 2 jenis karakter (huruf kecil, huruf besar, angka, simbol/spasi).';
	}
	return '';
}

// Tujuan setelah login: pakai cookie targeturl bawaan openDCIM, tetapi hanya bila
// berupa path di situs ini (mencegah open redirect).
function localauth_safe_target() {
	if ( isset( $_COOKIE['targeturl'] ) ) {
		$t = html_entity_decode( (string)$_COOKIE['targeturl'] );
		if ( preg_match( '#^/(?!/)[^\r\n\\\\]*$#', $t ) && stripos( $t, 'login_ldap.php' ) === false ) {
			return $t;
		}
	}
	return redirect( 'index.php' );
}

} // end if !function_exists
