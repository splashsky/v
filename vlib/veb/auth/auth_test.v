import veb.auth as vauth
import db.sqlite

fn test_password_hash() {
	db := sqlite.connect(':memory:') or { panic(err) }

	auth := vauth.new(db, vauth.Strategy.bcrypt)

	pass := 'test-Passw0rd-1234!@#'
	hash := auth.hash_password(pass)!

	assert auth.check_password(pass, hash)!
}

fn test_token() {
	db := sqlite.connect(':memory:') or { panic(err) }

	auth := vauth.new(db, vauth.Strategy.bcrypt)

	user_id := 1
	token := auth.add_token(user_id)!

	assert token.token.len > 0

	tok := auth.find_token_by_id(user_id)?

	assert tok.token == token.token

	auth.delete_tokens(user_id) or { panic(err) }

	assert auth.find_token_by_id(user_id) == none
}
