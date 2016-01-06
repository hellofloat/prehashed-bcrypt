prehashed-bcrypt
=========

prehashed-bcrypt will handle pre-hashing a password before passing it to bcrypt.
This avoids the issue of bcrypt having a 72 byte input limit, provided you
choose a hashing algorithm that produces hashes shorter than 72 bytes (base64-encoded).
SHA384 is a potentially good choice, producing hashes that are 64 bytes wide.

## Installation

```
npm install --save prehashed-bcrypt
```

## Usage

```javascript
var prehashedBcrypt = require( 'prehashed-bcrypt' );

prehashedBcrypt.hash( password, 'sha384', function( error, hash ) {
    // hash is now your hashed + salted + bcrypted password
    prehashedBcrypt.check( password, 'sha384', hash, function( error, result ) {
        // result is true, since the password hashed + bcrypt checked against
        // the existing hash
    } );
} );
```

## Methods

### hash( stringToHash, cryptoAlgorithm, callback )

Hashes the input string using the selected node.js crypto hashing algorithm, then
bcrypts the result. callback is a standard node.js callback: function( error, hash )

### check( stringToCheck, cryptoAlgorithm, existingHash, callback )

This checks the given string, pre-hashed using the given crypto algorithm against the
specified existing hash. callback is a standard node.js callback: function( error, result )

result is true if the input matched, false otherwise.

## Contributing

Pull requests are very welcome! Just make sure your code:

1) Passes jshint given the included .jshintrc

2) Is beautified using jsbeautifier and the included .jsbeautifyrc

## Why?

It's lame to have a limit on the length of your users passwords. Provided that the
pre-hashing algorithm selected is strong, this should be of equivalent security,
but allows for arbitrary length passwords.

See: http://security.stackexchange.com/a/6627

# CHANGELOG

v0.1.1
------
- Update README to avoid some markdown issues

v0.1.0
------
- Initial release.
