/* global describe, it */
'use strict';

var assert = require( 'better-assert' );
var prehashedBcrypt = require( '../index.js' );


describe( 'hashing', function() {
    var password = 'hello';

    it( 'hashes', function() {
        prehashedBcrypt.hash( password, 'sha384', function( error, hash ) {
            assert( error === null );
            assert( hash !== undefined );
        } );
    } );

    it( 'errors when pre-hashing algorithm output too long', function() {
        prehashedBcrypt.hash( password, 'sha512', function( error, hash ) {
            assert( error !== null );
            assert( hash === undefined );
        } );
    } );
} );

describe( 'hashing long password', function() {
    var shortPasswordChars = [];
    var longPasswordChars = [];

    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for ( var i = 0; i < 256; ++i ) {
        var char = possible.charAt( Math.floor( Math.random() * possible.length ) );
        if ( i < 72 ) {
            shortPasswordChars.push( char );
        }

        longPasswordChars.push( char );
    }

    var shortPassword = shortPasswordChars.join( '' );
    var longPassword = longPasswordChars.join( '' );

    it ( 'bcrypt sees no difference', function() {
        prehashedBcrypt.hash( shortPassword, null, function( error, shortHash ) {
            assert( error === null );
            assert( shortHash !== undefined );

            prehashedBcrypt.hash( longPassword, null, function( error, longHash ) {
                assert( error === null );
                assert( longHash !== undefined );

                prehashedBcrypt.check( longPassword, null, shortHash, function( error, result ) {
                    assert( error === null );
                    assert( result === true );
                } );
            } );
        } );
    } );

    var shortHash;
    var longHash;

    it( 'hashes short', function() {
        prehashedBcrypt.hash( shortPassword, 'sha384', function( error, hash ) {
            assert( error === null );
            assert( hash !== undefined );
            shortHash = hash;
        } );
    } );

    it( 'hashes long', function() {
        prehashedBcrypt.hash( longPassword, 'sha384', function( error, hash ) {
            assert( error === null );
            assert( hash !== undefined );
            longHash = hash;
        } );
    } );

    it( 'short and long hashes differ', function() {
        assert( shortHash !== longHash );
    } );

    it( 'short checks ok', function() {
        prehashedBcrypt.check( shortPassword, 'sha384', shortHash, function( error, result ) {
            assert( error === null );
            assert( result === true );
        } );
    } );

    it( 'long checks ok', function() {
        prehashedBcrypt.check( longPassword, 'sha384', longHash, function( error, result ) {
            assert( error === null );
            assert( result === true );
        } );
    } );

    it( 'long will not check ok for short', function() {
        prehashedBcrypt.check( longPassword, 'sha384', shortHash, function( error, result ) {
            assert( error === null );
            assert( result === false );
        } );
    } );
} );
