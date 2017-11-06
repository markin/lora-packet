"use strict";

let util = require('./util.js')("lora-packet crypto");

let CryptoJS = require("crypto-js");
let crypto = require('crypto');

let errHdr = "decrypt error: ";

// brevity
//let checkDefined = util.checkDefined;
let checkBufferLength = util.checkBufferLength;
let checkBuffer = util.checkBuffer;

// IV is always zero
let LORA_IV = CryptoJS.enc.Hex.parse('00000000000000000000000000000000');

exports.decrypt = function (packet, AppSKey, NwkSKey) {
    let pktBufs = packet.getBuffers();
    checkBuffer(pktBufs.PHYPayload, "parsed packet");

    // calc number of (16-byte/128-bit) blocks
    let blocks = Math.ceil(pktBufs.FRMPayload.length / 16);

    // create what LoRaWAN calls "Sequence S"
    // TODO this should be (at least) in a Uint8Array for ease of import to cryptojs
    let plain_S = new Buffer(16 * blocks);
    for (let block = 0; block < blocks; block++) {
        let Ai = _metadataBlock_Ai(packet, block);
        Ai.copy(plain_S, block * 16);
    }

    // encrypt "Sequence S" with key to create cipherstream

    // #4.3.3  key depends on port
    let key = packet.getFPort() === 0 ? NwkSKey : AppSKey;
    // console.log(key.toString('hex'));
    checkBufferLength(key, "appropriate key", 16);

    // TODO is there a better way to get cryptojs to ingest message/key?
    let cipherstream_base64 = CryptoJS.AES.encrypt(
        CryptoJS.enc.Hex.parse(plain_S.toString('hex')),
        CryptoJS.enc.Hex.parse(key.toString('hex')), {
            mode: CryptoJS.mode.ECB,
            iv: LORA_IV,
            padding: CryptoJS.pad.NoPadding
        });
    let cipherstream = new Buffer(cipherstream_base64.toString(), 'base64');

    // create buffer for decrypted message
    let plaintextPayload = new Buffer(pktBufs.FRMPayload.length);

    // xor the cipherstream with payload to create plaintext
    for (let i = 0; i < pktBufs.FRMPayload.length; i++) {
        let Si = cipherstream.readUInt8(i);
        plaintextPayload.writeUInt8(Si ^ pktBufs.FRMPayload.readUInt8(i), i);
    }

    // TODO? provide a convenience conversion to UTF-8

    return plaintextPayload;
};

exports.encryptSessionKey = function (packet, appKey) {

    let ciphertext = CryptoJS.AES.encrypt(
        CryptoJS.lib.WordArray.create(packet),
        CryptoJS.lib.WordArray.create(appKey),
        {
            mode: CryptoJS.mode.ECB,
            iv: LORA_IV,
            padding: CryptoJS.pad.NoPadding
        }
    ).ciphertext.toString(CryptoJS.enc.Hex);
    return new Buffer(ciphertext, 'hex');
    // let enc = CryptoJS.AES.encrypt(
    //     CryptoJS.enc.Hex.parse(packet.toString('hex')),
    //     CryptoJS.enc.Hex.parse(appKey.toString('hex')), {
    //         mode: CryptoJS.mode.ECB,
    //         iv: LORA_IV,
    //         padding: CryptoJS.pad.ZeroPadding
    //     });
    //
    // return new Buffer(enc.toString(), 'base64');
};

exports.encryptJoinAccept = function (packet, appKey) {


    // let decipher = crypto.createDecipher('aes-128-ecb', new Buffer(appKey, 'hex'));
    // decipher.setAutoPadding(false);
    // let dec = decipher.update(packet, 'hex', 'base64');
    // dec += decipher.final('base64');

    let dec = CryptoJS.AES.decrypt(
        packet.toString('base64'),
        CryptoJS.enc.Hex.parse(appKey.toString('hex')), {
            mode: CryptoJS.mode.ECB,
            iv: LORA_IV,
            padding: CryptoJS.pad.NoPadding
        });

    return new Buffer(dec.toString(), 'hex');
};


// Encrypt stream mixes in metadata blocks, as Ai =
//   0x01
//   0x00 0x00 0x00 0x00
//   direction-uplink/downlink [1]
//   DevAddr [4]
//   FCnt as 32-bit, lsb first [4]
//   0x00
//   counter = i [1]

function _metadataBlock_Ai(packet, i) {

    // TODO common code
    let Dir;
    if (packet.getDir() == 'up') {
        Dir = util.bufferFromUInt8(0);
    } else if (packet.getDir() == 'down') {
        Dir = util.bufferFromUInt8(1);
    } else {
        throw new Error(errHdr + "expecting direction to be either 'up' or 'down'");
    }

    let Ai_buf = Buffer.concat([
        new Buffer("0100000000", 'hex'), // as spec
        Dir, // direction ('Dir')
        util.reverse(packet.getBuffers().DevAddr),
        util.reverse(packet.getBuffers().FCnt),
        util.bufferFromUInt16LE(0), // upper 2 bytes of FCnt (zeroes)
        util.bufferFromUInt8(0), // 0x00
        util.bufferFromUInt8(i + 1) // block number
    ]);

    return Ai_buf;
}