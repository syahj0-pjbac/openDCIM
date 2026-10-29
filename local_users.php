<?php
/*
	local_users.php

	Halaman kelola password login lokal.
	  - Semua user yang sudah login: ganti password sendiri.
	  - User dengan hak "Manage Site and Users" (SiteAdmin): atur/reset password user lain,
	    buat user baru, cabut login lokal, dan buka kunci login.

	Halaman ini bekerja di mode Apache (Directory Privacy) maupun mode login lokal, sehingga
	password awal admin bisa dibuat SEBELUM mode autentikasi diganti.
*/

	require_once( 'db.inc.php' );
	require_once( 'facilities.inc.php' );
	require_once( 'local_auth.inc.php' );

	$subheader = "Kelola Password Login Lokal";

	// Hanya user yang dikenal dan aktif di openDCIM
	if ( !$person || intval( $person->PersonID ) <= 0 || $person->Disabled ) {
		header( 'Location: ' . redirect( 'index.php' ) );
		exit;
	}

	localauth_init();

	$isAdmin = (bool)$person->SiteAdmin;
	$myId    = $person->UserID;
	$errors  = array();
	$notes   = array();

	function lu_post( $key ) {
		return isset( $_POST[$key] ) ? (string)$_POST[$key] : '';
	}

	/* ---------- Proses form ---------- */
	if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
		if ( !localauth_csrf_check( lu_post( 'csrf' ) ) ) {
			$errors[] = 'Sesi formulir kedaluwarsa. Muat ulang halaman lalu coba lagi.';
		} else {
			$action = lu_post( 'action' );

			/* --- Ganti password sendiri --- */
			if ( $action === 'change_own' ) {
				$cur  = lu_post( 'current' );
				$new  = lu_post( 'new' );
				$new2 = lu_post( 'new2' );
				$has  = localauth_has_password( $myId );
				$ukey = localauth_key_user( $myId );

				if ( $has && localauth_is_locked( $ukey, LOCALAUTH_USER_MAX_FAILS ) ) {
					$errors[] = 'Terlalu banyak percobaan gagal. Coba lagi dalam ' . intval( LOCALAUTH_LOCK_SECONDS / 60 ) . ' menit.';
				} elseif ( $has && !localauth_verify( $myId, $cur ) ) {
					localauth_record_failure( $ukey );
					$errors[] = 'Password saat ini salah.';
				} elseif ( $new !== $new2 ) {
					$errors[] = 'Konfirmasi password baru tidak cocok.';
				} elseif ( ( $perr = localauth_password_error( $new, $myId ) ) !== '' ) {
					$errors[] = $perr;
				} else {
					localauth_set_password( $myId, $new );
					localauth_clear( $ukey );
					$notes[] = 'Password Anda berhasil diubah.';
				}

			/* --- Atur / reset password user lain (admin) --- */
			} elseif ( $action === 'set_password' ) {
				if ( !$isAdmin ) {
					$errors[] = 'Hanya admin (Manage Site and Users) yang boleh melakukan ini.';
				} else {
					$row  = localauth_find_person( trim( lu_post( 'userid' ) ) );
					$new  = lu_post( 'new' );
					$new2 = lu_post( 'new2' );

					if ( !$row ) {
						$errors[] = 'User tidak ditemukan di openDCIM.';
					} elseif ( $new !== $new2 ) {
						$errors[] = 'Konfirmasi password tidak cocok.';
					} elseif ( ( $perr = localauth_password_error( $new, $row['UserID'] ) ) !== '' ) {
						$errors[] = $perr;
					} else {
						localauth_set_password( $row['UserID'], $new );
						localauth_clear( localauth_key_user( $row['UserID'] ) );
						$notes[] = 'Password untuk ' . $row['UserID'] . ' berhasil diatur.';
					}
				}

			/* --- Buat user baru (admin) --- */
			} elseif ( $action === 'create_user' ) {
				if ( !$isAdmin ) {
					$errors[] = 'Hanya admin (Manage Site and Users) yang boleh melakukan ini.';
				} else {
					$uid   = trim( lu_post( 'userid' ) );
					$first = trim( lu_post( 'first' ) );
					$last  = trim( lu_post( 'last' ) );
					$email = trim( lu_post( 'email' ) );
					$new   = lu_post( 'new' );
					$new2  = lu_post( 'new2' );

					if ( !preg_match( '/^[A-Za-z0-9._@+-]{3,100}$/', $uid ) ) {
						$errors[] = 'UserID hanya boleh huruf, angka, titik, garis bawah, @, + dan -, panjang 3-100 karakter.';
					} elseif ( $last === '' ) {
						$errors[] = 'Nama belakang wajib diisi.';
					} elseif ( $email !== '' && !filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
						$errors[] = 'Format email tidak valid.';
					} elseif ( localauth_find_person( $uid ) ) {
						$errors[] = 'UserID sudah ada. Gunakan "Atur / reset password" untuk user tersebut.';
					} elseif ( $new !== $new2 ) {
						$errors[] = 'Konfirmasi password tidak cocok.';
					} elseif ( ( $perr = localauth_password_error( $new, $uid ) ) !== '' ) {
						$errors[] = $perr;
					} else {
						try {
							$np = new People();
							$np->UserID          = $uid;
							$np->LastName        = $last;
							$np->FirstName       = $first;
							$np->Email           = $email;
							$np->Phone1          = '';
							$np->Phone2          = '';
							$np->countryCode     = '';
							$np->APIKey          = '';
							$np->ExpirationDate  = '';
							$np->AdminOwnDevices = 0;
							$np->ReadAccess      = 1;   // hanya baca; hak lain diatur di User Administration
							$np->WriteAccess     = 0;
							$np->DeleteAccess    = 0;
							$np->ContactAdmin    = 0;
							$np->RackRequest     = 0;
							$np->RackAdmin       = 0;
							$np->BulkOperations  = 0;
							$np->SiteAdmin       = 0;
							$np->Disabled        = 0;

							if ( $np->CreatePerson() ) {
								localauth_set_password( $uid, $new );
								$notes[] = 'User ' . $uid . ' dibuat dengan hak baca saja. Atur hak lainnya di User Administration.';
							} else {
								$errors[] = 'Gagal membuat user di openDCIM. Periksa error_log.';
							}
						} catch ( PDOException $e ) {
							error_log( 'local_users: gagal membuat user: ' . $e->getMessage() );
							$errors[] = 'Gagal membuat user di openDCIM. Periksa error_log.';
						}
					}
				}

			/* --- Cabut login lokal (admin) --- */
			} elseif ( $action === 'remove_login' ) {
				$uid = trim( lu_post( 'userid' ) );
				if ( !$isAdmin ) {
					$errors[] = 'Hanya admin (Manage Site and Users) yang boleh melakukan ini.';
				} elseif ( strcasecmp( $uid, $myId ) == 0 ) {
					$errors[] = 'Anda tidak bisa mencabut login Anda sendiri.';
				} else {
					localauth_remove_password( $uid );
					$notes[] = 'Login lokal untuk ' . $uid . ' dicabut. User tersebut tidak bisa masuk lagi sampai diberi password baru.';
				}

			/* --- Buka kunci login (admin) --- */
			} elseif ( $action === 'unlock' ) {
				if ( !$isAdmin ) {
					$errors[] = 'Hanya admin (Manage Site and Users) yang boleh melakukan ini.';
				} else {
					localauth_clear( localauth_key_user( lu_post( 'userid' ) ) );
					$notes[] = 'Kunci login dibuka untuk ' . lu_post( 'userid' ) . '.';
				}

			} elseif ( $action === 'unlock_all' ) {
				if ( !$isAdmin ) {
					$errors[] = 'Hanya admin (Manage Site and Users) yang boleh melakukan ini.';
				} else {
					$dbh->exec( "DELETE FROM fac_LoginAttempts" );
					$notes[] = 'Semua kunci login dibuka.';
				}
			}
		}
	}

	/* ---------- Data untuk tampilan (khusus admin) ---------- */
	$users = array();
	$hasLogin = array();
	$lockedKeys = array();

	if ( $isAdmin ) {
		$st = $dbh->query( "SELECT UserID, FirstName, LastName, Disabled, ReadAccess, WriteAccess, ContactAdmin, SiteAdmin
			FROM fac_People ORDER BY UserID" );
		$users = $st->fetchAll( PDO::FETCH_ASSOC );

		$st = $dbh->query( "SELECT UserID, UpdatedAt FROM fac_LocalAuth" );
		foreach ( $st->fetchAll( PDO::FETCH_ASSOC ) as $r ) {
			$hasLogin[strtolower( $r['UserID'] )] = $r['UpdatedAt'];
		}

		$st = $dbh->prepare( "SELECT AttemptKey FROM fac_LoginAttempts
			WHERE LEFT(AttemptKey, 2) = 'u:' AND Attempts >= :m
			AND TIMESTAMPDIFF(SECOND, LastAttempt, NOW()) <= :w" );
		$st->bindValue( ':m', LOCALAUTH_USER_MAX_FAILS, PDO::PARAM_INT );
		$st->bindValue( ':w', LOCALAUTH_LOCK_SECONDS, PDO::PARAM_INT );
		$st->execute();
		foreach ( $st->fetchAll( PDO::FETCH_COLUMN ) as $k ) {
			$lockedKeys[$k] = true;
		}
	}

	$myHasLogin = localauth_has_password( $myId );
	$csrf = localauth_csrf_token();
?>
<!doctype html>
<html>
<head>
  <meta http-equiv="X-UA-Compatible" content="IE=Edge">
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <title>openDCIM - Kelola Password</title>
  <link rel="stylesheet" href="css/inventory.php" type="text/css">
  <link rel="stylesheet" href="css/jquery-ui.css" type="text/css">
  <!--[if lt IE 9]>
  <link rel="stylesheet"  href="css/ie.css" type="text/css">
  <![endif]-->

  <script type="text/javascript" src="scripts/jquery.min.js"></script>
  <script type="text/javascript" src="scripts/jquery-ui.min.js"></script>
</head>
<body>
<?php include( 'header.inc.php' ); ?>

<div class="page">
<?php include( 'sidebar.inc.php' ); ?>
<div class="main">
<div class="center"><div>

<?php
foreach ( $errors as $e ) {
	echo '<h3 style="color:#b00020;">', la_h( $e ), '</h3>';
}
foreach ( $notes as $n ) {
	echo '<h3 style="color:#1b6e2d;">', la_h( $n ), '</h3>';
}
?>

<h3>Ganti password saya (<?php echo la_h( $myId ); ?>)</h3>
<?php if ( !$myHasLogin ) { ?>
<p>Akun ini belum punya password login lokal. Cukup isi password baru (tanpa password saat ini).</p>
<?php } ?>
<form method="post" autocomplete="off">
<input type="hidden" name="csrf" value="<?php echo la_h( $csrf ); ?>">
<input type="hidden" name="action" value="change_own">
<div class="table">
<?php if ( $myHasLogin ) { ?>
  <div>
    <div><label for="current">Password saat ini:</label></div>
    <div><input type="password" id="current" name="current" autocomplete="current-password" maxlength="1024"></div>
  </div>
<?php } ?>
  <div>
    <div><label for="new_own">Password baru:</label></div>
    <div><input type="password" id="new_own" name="new" autocomplete="new-password" maxlength="72"></div>
  </div>
  <div>
    <div><label for="new2_own">Ulangi password baru:</label></div>
    <div><input type="password" id="new2_own" name="new2" autocomplete="new-password" maxlength="72"></div>
  </div>
  <div>
    <div></div>
    <div><button type="submit">Simpan password</button></div>
  </div>
</div>
</form>
<p><small>Minimal <?php echo LOCALAUTH_MIN_PASSWORD; ?> karakter, memuat minimal 2 jenis karakter, tidak sama dengan username.</small></p>

<?php if ( $isAdmin ) { ?>
<hr>
<h3>Atur / reset password user</h3>
<form method="post" autocomplete="off">
<input type="hidden" name="csrf" value="<?php echo la_h( $csrf ); ?>">
<input type="hidden" name="action" value="set_password">
<div class="table">
  <div>
    <div><label for="sp_user">User:</label></div>
    <div>
      <select id="sp_user" name="userid">
<?php foreach ( $users as $u ) {
	echo '<option value="', la_h( $u['UserID'] ), '">', la_h( $u['UserID'] ), '</option>';
} ?>
      </select>
    </div>
  </div>
  <div>
    <div><label for="sp_new">Password baru:</label></div>
    <div><input type="password" id="sp_new" name="new" autocomplete="new-password" maxlength="72"></div>
  </div>
  <div>
    <div><label for="sp_new2">Ulangi password:</label></div>
    <div><input type="password" id="sp_new2" name="new2" autocomplete="new-password" maxlength="72"></div>
  </div>
  <div>
    <div></div>
    <div><button type="submit">Simpan</button></div>
  </div>
</div>
</form>

<hr>
<h3>Buat user baru</h3>
<p>User baru dibuat dengan hak baca saja. Hak lain diatur di <a href="usermgr.php">User Administration</a>.</p>
<form method="post" autocomplete="off">
<input type="hidden" name="csrf" value="<?php echo la_h( $csrf ); ?>">
<input type="hidden" name="action" value="create_user">
<div class="table">
  <div>
    <div><label for="cu_user">UserID (username login):</label></div>
    <div><input type="text" id="cu_user" name="userid" maxlength="100" autocomplete="off"></div>
  </div>
  <div>
    <div><label for="cu_first">Nama depan:</label></div>
    <div><input type="text" id="cu_first" name="first" maxlength="40"></div>
  </div>
  <div>
    <div><label for="cu_last">Nama belakang:</label></div>
    <div><input type="text" id="cu_last" name="last" maxlength="40"></div>
  </div>
  <div>
    <div><label for="cu_email">Email:</label></div>
    <div><input type="text" id="cu_email" name="email" maxlength="80"></div>
  </div>
  <div>
    <div><label for="cu_new">Password:</label></div>
    <div><input type="password" id="cu_new" name="new" autocomplete="new-password" maxlength="72"></div>
  </div>
  <div>
    <div><label for="cu_new2">Ulangi password:</label></div>
    <div><input type="password" id="cu_new2" name="new2" autocomplete="new-password" maxlength="72"></div>
  </div>
  <div>
    <div></div>
    <div><button type="submit">Buat user</button></div>
  </div>
</div>
</form>

<hr>
<h3>Daftar user</h3>
<div style="overflow-x:auto;">
<table class="border" style="border-collapse:collapse;" cellpadding="4">
<tr>
  <th>UserID</th><th>Nama</th><th>Hak</th><th>Status</th><th>Login lokal</th><th>Aksi</th>
</tr>
<?php
foreach ( $users as $u ) {
	$rights = array();
	if ( $u['ReadAccess'] )   { $rights[] = 'Read'; }
	if ( $u['WriteAccess'] )  { $rights[] = 'Write'; }
	if ( $u['ContactAdmin'] ) { $rights[] = 'Contacts'; }
	if ( $u['SiteAdmin'] )    { $rights[] = 'SiteAdmin'; }

	$lk = strtolower( $u['UserID'] );
	$hasPw = isset( $hasLogin[$lk] );
	$locked = isset( $lockedKeys[localauth_key_user( $u['UserID'] )] );

	echo '<tr style="border-top:1px solid #999;">';
	echo '<td>', la_h( $u['UserID'] ), '</td>';
	echo '<td>', la_h( trim( $u['FirstName'] . ' ' . $u['LastName'] ) ), '</td>';
	echo '<td>', la_h( implode( ', ', $rights ) ), '</td>';
	echo '<td>', ( $u['Disabled'] ? 'Nonaktif' : 'Aktif' ), ( $locked ? ' / TERKUNCI' : '' ), '</td>';
	echo '<td>', ( $hasPw ? 'Ada (' . la_h( $hasLogin[$lk] ) . ')' : 'Belum ada' ), '</td>';
	echo '<td>';

	if ( $locked ) {
		echo '<form method="post" style="display:inline;">',
			'<input type="hidden" name="csrf" value="', la_h( $csrf ), '">',
			'<input type="hidden" name="action" value="unlock">',
			'<input type="hidden" name="userid" value="', la_h( $u['UserID'] ), '">',
			'<button type="submit">Buka kunci</button></form> ';
	}
	if ( $hasPw && strcasecmp( $u['UserID'], $myId ) != 0 ) {
		echo '<form method="post" style="display:inline;" onsubmit="return confirm(\'Cabut login lokal user ini?\');">',
			'<input type="hidden" name="csrf" value="', la_h( $csrf ), '">',
			'<input type="hidden" name="action" value="remove_login">',
			'<input type="hidden" name="userid" value="', la_h( $u['UserID'] ), '">',
			'<button type="submit">Cabut login</button></form>';
	}
	echo '</td></tr>';
}
?>
</table>
</div>

<form method="post" style="margin-top:10px;">
<input type="hidden" name="csrf" value="<?php echo la_h( $csrf ); ?>">
<input type="hidden" name="action" value="unlock_all">
<button type="submit">Buka semua kunci login</button>
</form>
<?php } // end isAdmin ?>

<br>
</div></div>
<a href="index.php">[ Kembali ke menu utama ]</a>
<?php if ( $person->ContactAdmin ) { ?>
 &nbsp; <a href="usermgr.php">[ User Administration ]</a>
<?php } ?>
</div><!-- END div.main -->
</div><!-- END div.page -->
</body>
</html>
