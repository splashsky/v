import veb.auth as vauth
import db.sqlite

fn test_password_hash() {
	db := sqlite.connect(':memory:') or { panic(err) }

	auth := vauth.new(db)

	pass := 'test-Passw0rd-1234!@#'
	hash := auth.hash_password(pass)!

	assert auth.check_password(pass, hash)!
}