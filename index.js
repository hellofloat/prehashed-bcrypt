'use strict';

var bcrypt = require( 'bcryptjs' );
var crypto = require( 'crypto' );

function hashPassword( password, hashAlgo, callback ) {
    if ( hashAlgo === null ) {
        callback( null, password );
        return;
    }

    var hasher = crypto.createHash( hashAlgo );
    hasher.update( password );
    var hashed = hasher.digest( 'base64' );

    if ( hashed.length > 72 ) {
        callback( 'Hashing algorithm \'' + hashAlgo + '\' produced a hash > 72 bytes long, which is not supported by bcrypt.' );
        return;
    }

    callback( null, hashed );
}

module.exports = {
    hash: function( password, hashAlgo, callback ) {
        hashPassword( password, hashAlgo, function( error, hashed ) {
            if ( error ) {
                callback( error );
                return;
            }

            bcrypt.hash( hashed, 10, callback );
        } );
    },

    check: function( password, hashAlgo, stored, callback ) {
        hashPassword( password, hashAlgo, function( error, hashed ) {
            if ( error ) {
                callback( error );
                return;
            }

            bcrypt.compare( hashed, stored, callback );
        } );
    }
};
