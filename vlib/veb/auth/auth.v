// Copyright (c) 2019-2024 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module auth

import rand
import crypto.bcrypt

// Strategies for password hashing.
// - bcrypt - The default strategy. Uses a sensible default cost.
pub enum Strategy as u8 {
	bcrypt
}

pub struct Auth[T] {
	db       T
	strategy Strategy
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
pub fn new[T](db T, strategy Strategy) Auth[T] {
	sql db {
		create table Token
	} or { eprintln('veb.auth: failed to create table Token') }

	return Auth[T]{
		db: db
		strategy: strategy
	}
}

// Insert an authentication token with the user's ID.
pub fn (app Auth[T]) add_token(user_id int) !Token {
	mut uuid := rand.uuid_v4()

	token := Token{
		user_id: user_id
		token: uuid
	}

	sql app.db {
		insert token into Token
	}!

	return token
}

// Find a user's token by their user ID.
pub fn (a Auth[T]) find_token_by_id(user_id int) ?Token {
	tokens := sql a.db {
		select from Token where user_id == user_id limit 1
	} or { []Token{} }

	if tokens.len == 0 {
		return none
	}

	return tokens.first()
}

// Delete all tokens associated with the user ID.
pub fn (a Auth[T]) delete_tokens(user_id int) ! {
	sql a.db {
		delete from Token where user_id == user_id
	}!
}

// Hash a password using the chosen hashing strategy.
pub fn (a Auth[T]) hash_password(password string) !string {
	return match a.strategy {
		.bcrypt { bcrypt.generate_from_password(password.bytes(), 10)! }
	}
}

// Check a hashed password using the chosen hashing strategy.
pub fn (a Auth[T]) check_password(password string, hash string) !bool {
	match a.strategy {
		.bcrypt {
			bcrypt.compare_hash_and_password(password.bytes(), hash.bytes())!
			return true
		}
	}
}
