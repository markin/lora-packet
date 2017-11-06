"use strict";

let packet = require('./packet.js');

/**
 * LoRa MIC calculation and checking
 *
 * See LoRa spec #4.4 "Message Integrity Code (MIC)"
 *
 *
 * MIC calculated over
 *      B0 | MHDR | FHDR | FPort | FRMPayload
 *  ( = B0 | MHDR | MACPayload )
 *
 * where B0 =
 *   0x49
 *   0x00 0x00 0x00 0x00
 *   direction-uplink/downlink [1]
 *   DevAddr [4]
 *   FCnt as 32-bit, lsb first [4]
 *   0x00
 *   message length [1]
 *
 */

let aesCmac = require('node-aes-cmac').aesCmac;

let util = require('./util.js')("lora-packet verify");
let checkDefined = util.checkDefined;
let checkBufferLength = util.checkBufferLength;
let checkBuffer = util.checkBuffer;


// calculate MIC from packet
exports.calculateMIC = function (packet, NwkSKey) {
    let pktBufs = packet.getBuffers();

    checkBuffer(pktBufs.PHYPayload, "pktBufs packet");
    checkBufferLength(NwkSKey, "NwkSKey", 16);

    checkBufferLength(pktBufs.DevAddr, "pktBufs packet.DevAddr", 4);
    checkBufferLength(pktBufs.FCnt, "pktBufs packet.FCnt", 2);

    checkBuffer(pktBufs.MHDR, "pktBufs packet.MHDR");
    checkBuffer(pktBufs.MACPayload, "pktBufs packet.MACPayload");

    let Dir;
    if (packet.getDir() == 'up') {
        Dir = util.bufferFromUInt8(0);
    } else if (packet.getDir() == 'down') {
        Dir = util.bufferFromUInt8(1);
    } else {
        throw new Error(errHdr + "expecting direction to be either 'up' or 'down'");
    }

    let msglen = pktBufs.MHDR.length + pktBufs.MACPayload.length;

    let B0 = Buffer.concat([
        new Buffer("4900000000", 'hex'),    // as spec
        Dir,  // direction ('Dir')
        util.reverse(pktBufs.DevAddr),
        util.reverse(pktBufs.FCnt),
        util.bufferFromUInt16LE(0),    // upper 2 bytes of FCnt (zeroes)
        util.bufferFromUInt8(0),    // 0x00
        util.bufferFromUInt8(msglen)     // len(msg)
    ]);

    // CMAC over B0 | MHDR | MACPayload
    let cmac_input = Buffer.concat([B0, pktBufs.MHDR, pktBufs.MACPayload]);

    // CMAC calculation (as RFC4493)
    let full_cmac = aesCmac(NwkSKey, cmac_input, {returnAsBuffer: true});

    // only first 4 bytes of CMAC are used as MIC
    let MIC = full_cmac.slice(0, 4);

    return MIC;
};

exports.calculateJoinRequestMIC = function (packet, AppKey) {
    let pktBufs = packet.getBuffers();
    let cmac_input = Buffer.concat([pktBufs.MHDR, pktBufs.AppEUI, pktBufs.DevEUI, pktBufs.DevNonce]);
    let full_cmac = aesCmac(AppKey, cmac_input, {returnAsBuffer: true});

    return full_cmac.slice(0, 4);
};

exports.calculateJoinAcceptMIC = function (packet, AppKey) {
    let pktBufs = packet;
    //console.log(packet);
    let cmac_input = Buffer.concat([pktBufs.MHDR, pktBufs.AppNonce, pktBufs.NetID, pktBufs.DevAddr,
        pktBufs.DLSettings, pktBufs.RxDelay]);
    //console.log("CMAC INPUT",cmac_input);

    let full_cmac = aesCmac(AppKey, cmac_input, {returnAsBuffer: true});

    //console.log("CMAC OUTPUT",full_cmac.slice(0, 4));

    return full_cmac.slice(0, 4);
};

exports.verifyJoinRequestMIC = function (packet, AppKey) {
    let pktBufs = packet.getBuffers();
    let calculated = exports.calculateJoinRequestMIC(packet, AppKey);
    return util.areBuffersEqual(pktBufs.MIC, calculated);
};

exports.recalculateJoinRequestMIC = function (packet, AppKey) {
    let calculated = exports.calculateJoinRequestMIC(packet, AppKey);
    let pktBufs = packet.getBuffers();
    pktBufs.MIC = calculated;
};

// verify is just calculate & compare
exports.verifyMIC = function (packet, NwkSKey) {
    let pktBufs = packet.getBuffers();
    checkBufferLength(pktBufs.MIC, "pktBufs packet.MIC", 4);

    let calculated = exports.calculateMIC(packet, NwkSKey);
    return util.areBuffersEqual(pktBufs.MIC, calculated);
};

// calculate MIC & store
exports.recalculateMIC = function (packet, NwkSKey) {
    let calculated = exports.calculateMIC(packet, NwkSKey);
    let pktBufs = packet.getBuffers();
    pktBufs.MIC = calculated;
};



