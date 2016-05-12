'use strict';

const async = require( 'async' );
const prehashedBcrypt = require( '../index.js' );
const test = require( 'tape' );

test( 'hashes', ( t ) => {
    prehashedBcrypt.hash( 'password', 'sha384', function( error, hash ) {
        t.error( error, 'no error' );
        t.ok( hash, 'hashed' );
        t.end();
    } );
} );

test( 'errors when pre-hashing algorithm output too long', ( t ) => {
    prehashedBcrypt.hash( 'password', 'sha512', function( error, hash ) {
        t.ok( error, 'got error' );
        t.notOk( hash, 'no hash' );
        t.end();
    } );
} );

const data = {};

test( 'create passwords', ( t ) => {
    let shortPasswordChars = [];
    let longPasswordChars = [];

    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for ( var i = 0; i < 1024; ++i ) {
        var char = possible.charAt( Math.floor( Math.random() * possible.length ) );
        if ( i < 72 ) {
            shortPasswordChars.push( char );
        }

        longPasswordChars.push( char );
    }

    data.shortPassword = shortPasswordChars.join( '' );
    data.longPassword = longPasswordChars.join( '' );

    t.ok( data.shortPassword, 'generated short password' );
    t.equal( data.shortPassword.length, 72, 'short password is 72 chars long' );
    t.ok( data.longPassword, 'generated long password' );
    t.equal( data.longPassword.length, 1024, 'long password is 1024 chars long' );
    t.notEqual( data.shortPassword, data.longPassword, 'short and long generated passwords differ' );
    t.end();
} );

test( 'plain bcrypt sees short and long passwords as the same', ( t ) => {
    let shortBcrypted = null;
    let longBcrypted = null;
    async.series( [
        next => {
            prehashedBcrypt.hash( data.shortPassword, null, ( error, _shortBcrypted ) => {
                shortBcrypted = _shortBcrypted;
                t.ok( shortBcrypted, 'bcrypted short password' );
                next( error );
            } );
        },

        next => {
            prehashedBcrypt.hash( data.longPassword, null, ( error, _longBcrypted ) => {
                longBcrypted = _longBcrypted;
                t.ok( longBcrypted, 'bcrypted long password' );
                next( error );
            } );
        },

        next => {
            prehashedBcrypt.check( data.longPassword, null, shortBcrypted, ( error, result ) => {
                t.ok( result, 'plain bcrypt thinks the long password and short bcrypted result go together fine' );
                next( error );
            } );
        }
    ], ( error ) => {
        if ( error ) {
            t.fail( error );
        }

        t.end();
    } );
} );

test( 'hash+bcrypt short password', ( t ) => {
    prehashedBcrypt.hash( data.shortPassword, 'sha384', ( error, bcrypted ) => {
        t.error( error, 'no error' );
        t.ok( bcrypted, 'hashed+bcrypted' );
        data.shortHash = bcrypted;
        t.end();
    } );
} );

test( 'hash+bcrypt long password', ( t ) => {
    prehashedBcrypt.hash( data.longPassword, 'sha384', ( error, bcrypted ) => {
        t.error( error, 'no error' );
        t.ok( bcrypted, 'hashed+bcrypted' );
        data.longHash = bcrypted;
        t.end();
    } );
} );

test( 'short and long hashes differ', ( t ) => {
    t.notEqual( data.shortHash, data.longHash, 'different' );
    t.end();
} );

test( 'password hashes differ correctly', ( t ) => {
    async.series( [
        next => {
            prehashedBcrypt.check( data.shortPassword, 'sha384', data.shortHash, ( error, result ) => {
                t.ok( result, 'short password vs. short hash check passed' );
                next( error );
            } );
        },

        next => {
            prehashedBcrypt.check( data.longPassword, 'sha384', data.longHash, ( error, result ) => {
                t.ok( result, 'long password vs. long hash check passed' );
                next( error );
            } );
        },

        next => {
            prehashedBcrypt.check( data.shortPassword, 'sha384', data.longHash, ( error, result ) => {
                t.notOk( result, 'short password vs. long hash check failed' );
                next( error );
            } );
        },

        next => {
            prehashedBcrypt.check( data.longPassword, 'sha384', data.shortHash, ( error, result ) => {
                t.notOk( result, 'long password vs. short hash check failed' );
                next( error );
            } );
        }
    ], ( error ) => {
        if ( error ) {
            t.fail( error );
        }

        t.end();
    } );
} );