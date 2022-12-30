/* eslint-disable indent */
import { createCipheriv, createDecipheriv, pbkdf2Sync } from 'browser-crypto';
import { Buffer } from 'buffer';
import randomBytes from 'randombytes';

export default class AESGCMUtil {
    constructor() {
        this._keySize = 256;
        // this._ivSize = 128;
        this._ivSize = 12;
        // this._iterationCount = 1989;
        this._iterationCount = 65536;
    }

    encrypt( text, masterkey ) {
        // random initialization vector
        // const iv = crypto.randomBytes( 16 );
        const iv = randomBytes( 16 );

        // random salt
        // const salt = crypto.randomBytes( 64 );
        const salt = randomBytes( 64 );

        // derive encryption key: 32 byte key length
        // in assumption the masterkey is a cryptographic and NOT a password there is no need for
        // a large number of iterations. It may can replaced by HKDF
        // the value of 2145 is randomly chosen!
        // const key = pbkdf2.pbkdf2Sync( masterkey, salt, 2145, 32, 'sha512' );
        const key = pbkdf2Sync( masterkey, salt, 2145, 32, 'sha512' );

        // AES 256 GCM Mode
        // const cipher = crypto.createCipheriv( 'aes-256-gcm', key, iv );
        const cipher = createCipheriv( 'aes-256-gcm', key, iv );

        // encrypt the given text
        const encrypted = Buffer.concat( [
            cipher.update( text, 'utf8' ),
            cipher.final()
        ] );

        // extract the auth tag
        const tag = cipher.getAuthTag();

        // generate output
        return Buffer.concat( [ salt, iv, tag, encrypted ] ).toString( 'base64' );
    }

    decrypt( encdata, masterkey ) {
        // base64 decoding
        const bData = Buffer.from( encdata, 'base64' );
        // const bData = new Buffer( encdata, 'base64' );

        // convert data to buffers
        const salt = bData.slice( 0, 64 );
        // let salt = encdata.substr( 0, 64 );
        const iv = bData.slice( 64, 80 );
        const tag = bData.slice( 80, 96 );
        const text = bData.slice( 96 );

        // derive key using; 32 byte key length
        // const key = crypto.pbkdf2Sync( masterkey, salt, 2145, 32, 'sha512' );
        const key = pbkdf2Sync( masterkey, salt, 2145, 32, 'sha512' );
        // const key = PBKDF2.getKey( masterkey, salt, { keySize: 32, iterations: 2145 } );

        // AES 256 GCM Mode
        // const decipher = crypto.createDecipheriv( 'aes-256-gcm', key, iv );
        const decipher = createDecipheriv( 'aes-256-gcm', key, iv );
        decipher.setAuthTag( tag );

        // encrypt the given text
        return decipher.update( text, 'binary', 'utf8' ) + decipher.final( 'utf8' );
    }
}
