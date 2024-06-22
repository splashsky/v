// Copyright (c) 2019-2024 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module auth

import rand
import crypto.bcrypt

// Strategies for password hashing.
// - bcrypt - The default strategy. Uses a sensible default cost.
enum Strategy as u8 {
	bcrypt
}

pub struct Auth[T] {
	db T
	strategy u8
}

@[table: 'tokens']
pub struct Token {
pub:
	user_id int    @[primary; unique]
	token   string
	// implement expiration?
	// implement IP tracking?
}

// Initialize an instance of Auth with your database driver of choice.
// This will create the 'tokens' table with the 'Token' struct.
// 
// You can also optionally define a password hashing strategy from the 
// auth.Strategy enum; this defaults to bcrypt (0).
pub fn new[T](db T, strategy ?u8) Auth[T] {
	sql db {
		create table Token
	} or { eprintln('veb.auth: failed to create table Token') }

	if strategy == none {
		strategy = auth.Strategy.bcrypt
	}

	return Auth[T] {
		db: db
		strategy: strategy
	}
}

// Insert an authentication token with the user's ID.
pub fn (mut app Auth[T]) add_token(user_id int) !string {
	mut uuid := rand.uuid_v4()

	token := Token{
		user_id: user_id
		value: uuid
	}

	sql app.db {
		insert token into Token
	}!

	return uuid
}

// Find a user's token by their user ID.
pub fn (app &Auth[T]) find_token_by_id(user_id int) ?Token {
	tokens := sql app.db {
		select from Token where user_id == user_id limit 1
	} or { []Token{} }

	if tokens.len == 0 {
		return none
	}

	return tokens.first()
}

// Delete all tokens associated with the user ID.
pub fn (mut app Auth[T]) delete_tokens(user_id int) ! {
	sql app.db {
		delete from Token where user_id == user_id
	}!
}

// Hash a password using the chosen hashing strategy.
fn (mut a Auth[T]) hash_password(password string) !string {
	return match a.strategy {
		0 { bcrypt.generate_from_password(password.bytes(), 15)! }
		else { bcrypt.generate_from_password(password.bytes(), 15)! }
	}
}

// Check a hashed password using the chosen hashing strategy.
fn (mut a Auth[T]) check_password(password string, hash string) bool {
	return match a.strategy {
		0 { bcrypt.compare_hash_and_password(password.bytes(), hash.bytes())! }
		else { bcrypt.compare_hash_and_password(password.bytes(), hash.bytes())! }
	}
}
