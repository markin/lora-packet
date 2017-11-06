'use strict';

var _mic = require('mic');

var mic = require('./mic.js');
var crypt = require('./crypt.js');
var packet = require('./packet.js');

var util = require('./util.js')("");

module.exports = {
    fromWire: packet.fromWire,
    fromFields: _constructPacketFromFields,
    constructJoinAccept: _constructJoinAccept,
    buildNwkSKey: _buildNwkSKey,
    buildAppSKey: _buildAppSKey,

    verifyMIC: mic.verifyMIC,
    calculateMIC: mic.calculateMIC,
    recalculateMIC: mic.recalculateMIC,
    calculateJoinRequestMIC: mic.calculateJoinRequestMIC,
    verifyJoinRequestMIC: mic.verifyJoinRequestMIC,
    recalculateJoinRequestMIC: mic.recalculateJoinRequestMIC,
    calculateJoinAcceptMIC: mic.calculateJoinAcceptMIC,

    decrypt: crypt.decrypt,
    encryptJoinAccept: crypt.encryptJoinAccept,

    constants: packet.constants,

    // deprecated
    getMIC: mic.calculateMIC,
    create: packet.fromWire,

    reverse: util.reverse
};

// to create a packet from fields, it's necessary to pull together
//  all three modules (packet.js, mic.js, crypt.js)
function _constructPacketFromFields(userFields, AppSKey, NwkSKey) {
    // if user fails to supply keys, construct a packet anyway
    var constructed = packet.fromFields(userFields);

    if (constructed != null) {
        // to encrypt, need NwkSKey if port=0, else AppSKey
        if (constructed.getFPort() == 0 && util.isBufferLength(NwkSKey, 16) || constructed.getFPort() > 0 && util.isBufferLength(AppSKey, 16)) {

            // crypto is reversible (just XORs FRMPayload), so we can
            //  just do "decrypt" on the plaintext to get ciphertext
            var ciphertext = crypt.decrypt(constructed, AppSKey, NwkSKey);

            // overwrite payload with ciphertext
            constructed.getBuffers().FRMPayload = ciphertext;

            // recalculate buffers to be ready for MIC calc'n
            constructed.mergeGroupFields();
        }

        if (util.isBufferLength(NwkSKey, 16)) {
            mic.recalculateMIC(constructed, NwkSKey);
            constructed.mergeGroupFields();
        }
    }

    return constructed;
}

function _constructJoinAccept(join_accept, appKey) {

    var MIC = (0, _mic.calculateJoinAcceptMIC)(join_accept, appKey);
    //console.log(join_accept);
    var payload = Buffer.concat([join_accept.AppNonce, join_accept.NetID, join_accept.DevAddr, join_accept.DLSettings, join_accept.RxDelay, MIC]);

    payload = crypt.encryptJoinAccept(payload, appKey);
    return Buffer.concat([join_accept.MHDR, payload]);
}

function _buildNwkSKey(join_accept, devNonce, appKey) {
    //console.log(join_accept.AppNonce, join_accept.NetID, devNonce);
    var payload = Buffer.concat([Buffer.from('01', 'hex'), join_accept.AppNonce, join_accept.NetID, devNonce, Buffer.from('00000000000000', 'hex')]);
    return crypt.encryptSessionKey(payload, appKey);
}

function _buildAppSKey(join_accept, devNonce, appKey) {
    var payload = Buffer.concat([Buffer.from('02', 'hex'), join_accept.AppNonce, join_accept.NetID, devNonce, Buffer.from('00000000000000', 'hex')]);
    return crypt.encryptSessionKey(payload, appKey);
}