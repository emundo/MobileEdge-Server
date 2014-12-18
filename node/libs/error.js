/*
 * This file is part of MobileEdge-Server, the server-side component
 * of the MobileEdge framework.
 * Copyright (c) 2014 eMundo GmbH

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Created by Raphael Arias on 2014-08-12.
 */

/**
 * @module error
 * @description Creation of error objects
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

var errorCodeMsgEnum = {
    ERROR_CODE_INVALID_FORMAT : 'Request did not contain valid JSON.',
    ERROR_CODE_ID_CREATION_FAILURE : 'Could not create ID. This is likely a backend failure.',
    ERROR_CODE_ID_REFRESHING_ID_NOT_GIVEN : 'No ID to refresh.',
    ERROR_CODE_ID_REFRESHING_FAILURE : 'Could not refresh ID. Is the given ID valid?',
    ERROR_CODE_KEYEXCHANGE_ID_NOT_GIVEN : 'No ID for key exchange.',
    ERROR_CODE_KEYEXCHANGE_ID_INVALID : 'Could not perform key exchange. Invalid ID.',
    ERROR_CODE_KEYEXCHANGE_NO_MESSAGE : 'No key exchange message.',
    ERROR_CODE_KEYEXCHANGE_FAILURE : 'Could not perform key exchange.',
    ERROR_CODE_ENCRYPTION_FAILURE : 'Internal error while encrypting.',
    ERROR_CODE_DECRYPTION_ID_NOT_GIVEN : 'Cannot decrypt. ID not given.',
    ERROR_CODE_DECRYPTION_ID_INVALID : 'Cannot decrypt. Invalid ID.',
    ERROR_CODE_DECRYPTION_NO_MESSAGE : 'No encrypted message.',
    ERROR_CODE_DECRYPTION_FAILURE : 'Internal error while decrypting.',
    ERROR_CODE_INVALID_INTERNAL_MESSAGE_FORMAT : 'Invalid message format. Decrypted message does not contain valid JSON.',
    ERROR_CODE_INVALID_INTERNAL_MESSAGE_TYPE : 'Decrypted message has no type.',
    ERROR_CODE_PREKEY_PUSH_NONEXISTENT_PREKEY : 'No prekey specified.',
    ERROR_CODE_PREKEY_PUSH_FAILURE : 'Could not store prekey.',
    ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_ID : 'Invalid key id.',
    ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_BASE : 'Invalid base key',
    ERROR_CODE_PREKEY_GET_ID_NOT_GIVEN : 'Could not fetch prekey. No identity specified.',
    ERROR_CODE_PREKEY_GET_ID_INVALID : 'Invalid identity. No prekey present.',
    ERROR_CODE_PREKEY_GET_NOT_FOUND : 'Could not find prekey.'
}

var errorCodeEnum = {
    ERROR_CODE_INVALID_FORMAT :                     10001,
    ERROR_CODE_ID_CREATION_FAILURE :                10002,
    ERROR_CODE_ID_REFRESHING_ID_NOT_GIVEN :         10003,
    ERROR_CODE_ID_REFRESHING_FAILURE :              10004,
    ERROR_CODE_KEYEXCHANGE_ID_NOT_GIVEN :           10005,
    ERROR_CODE_KEYEXCHANGE_ID_INVALID :             10006,
    ERROR_CODE_KEYEXCHANGE_NO_MESSAGE :             10007,
    ERROR_CODE_KEYEXCHANGE_FAILURE :                10008,
    ERROR_CODE_ENCRYPTION_FAILURE :                 10009,
    ERROR_CODE_DECRYPTION_ID_NOT_GIVEN :            10010,
    ERROR_CODE_DECRYPTION_ID_INVALID :              10011,
    ERROR_CODE_DECRYPTION_NO_MESSAGE :              10012,
    ERROR_CODE_DECRYPTION_FAILURE :                 10013,
    ERROR_CODE_INVALID_INTERNAL_MESSAGE_FORMAT :    10014,
    ERROR_CODE_INVALID_INTERNAL_MESSAGE_TYPE :      10015,
    ERROR_CODE_PREKEY_PUSH_NONEXISTENT_PREKEY :     10016,
    ERROR_CODE_PREKEY_PUSH_FAILURE :                10017,
    ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_ID :      10018,
    ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_BASE :    10019,
    ERROR_CODE_PREKEY_GET_ID_NOT_GIVEN :            10020,
    ERROR_CODE_PREKEY_GET_ID_INVALID :              10021,
    ERROR_CODE_PREKEY_GET_NOT_FOUND :               10022
}
/**
 * @description Error codes.
 *
 * @property ERROR_CODE_INVALID_FORMAT                                    
 * @property ERROR_CODE_ID_CREATION_FAILURE 
 * @property ERROR_CODE_ID_REFRESHING_ID_NOT_GIVEN
 * @property ERROR_CODE_ID_REFRESHING_FAILURE
 * @property ERROR_CODE_KEYEXCHANGE_ID_NOT_GIVEN 
 * @property ERROR_CODE_KEYEXCHANGE_ID_INVALID 
 * @property ERROR_CODE_KEYEXCHANGE_NO_MESSAGE 
 * @property ERROR_CODE_KEYEXCHANGE_FAILURE 
 * @property ERROR_CODE_ENCRYPTION_FAILURE 
 * @property ERROR_CODE_DECRYPTION_ID_NOT_GIVEN 
 * @property ERROR_CODE_DECRYPTION_ID_INVALID 
 * @property ERROR_CODE_DECRYPTION_NO_MESSAGE
 * @property ERROR_CODE_DECRYPTION_FAILURE
 * @property ERROR_CODE_INVALID_INTERNAL_MESSAGE_FORMAT 
 * @property ERROR_CODE_INVALID_INTERNAL_MESSAGE_TYPE 
 * @property ERROR_CODE_PREKEY_PUSH_NONEXISTENT_PREKEY 
 * @property ERROR_CODE_PREKEY_PUSH_FAILURE 
 * @property ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_ID 
 * @property ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_BASE 
 * @property ERROR_CODE_PREKEY_GET_ID_NOT_GIVEN 
 * @property ERROR_CODE_PREKEY_GET_ID_INVALID 
 * @property ERROR_CODE_PREKEY_GET_NOT_FOUND 
 * @static
 */
exports.errCodeEnum = errorCodeEnum;

/**
 * @description create an error object to be sent back to the client
 *
 * @param {String} errorCode - the error code as string
 * @param {?String} customMessage - an optional additional error message.
 * @return {Object} the error object containing error code, error message and possibly
 *      an additional message primarily for the application developer.
 */
exports.createErrorObject = function createErrorObject(errorCode, customMessage)
{
    return {
        'errCode' : errorCodeEnum[errorCode],
        'errMsg' : errorCodeMsgEnum[errorCode],
        'errDevMsg' : customMessage 
    };
}
