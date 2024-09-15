/** prefix for publickey record in remote mutable storage **/
const PUBKEY_PFX  = 'pgp.publickey';
/**
 * Bitflag state which tracks all possible states across the application lifetime
 *
 * @prop {number} DEV Application is running in developer mode
 * @prop {number} PANIC Application has panicked i.e. terminated abnormally
 * @prop {number} RTS Application is ready to submit content to the backend
 * @prop {number} SEND_ERROR Last attempt at sending content to the backend failed
 * @prop {number} SETTINGS Settings have been successfully loaded
 * @prop {number} REMOTE_KEY Remote encryption key has been successfully loaded
 * @prop {number} LOCAL_KEY Local private key exists in store
 * @prop {number} LOCAL_KEY_DECRYPTED Local private key has been decrypted and currently resides in memory
 * @prop {number} LOCAL_KEY_IDENTIFIED User has provided some identifiable information for the private key (there is no guarantee this is real or not, of course)
 * @prop {number} LOCAL_KEY_GENERATE A new local private key has been generated this session
 * @prop {number} PASSPHRASE_ACTIVE User has provided a passphrase to unlock the local key
 * @prop {number} PASSPHRASE_FAIL Last provided passphrase by user failed to unlock the local key
 * @prop {number} ACK_MESSAGE Data endpoint has confirmed receipt of message
 * @prop {number} ENC_MESSAGE Message was successfully encrypted locally (and is ready to be sent to remote)
 * @prop {number} ACK_PUBKEY Data endpoint has confirmed receipt of public key data for local key
 * @prop {number} ENC_PUBKEY Local key publickey was successfully encrypted locally (and is ready to be sent to remote)
 * @prop {number} ACK_COUNTER Data endpoint has confirmed receipt of updated message counter 
 * @prop {number} ENC_COUNTER Message counter was successfully encrypted locally (and is ready to be sent to remote)
 * @prop {number} HELP Application is providing contextual help
 * @prop {number} FILE_PROCESS A request to attach a file to the message has been initiated.
 * @prop {number} FILE_ADDED A request to attach a file has been successfully processed. Submission will now contain the file content as part of the message.
 **/
const STATE = {
	DEV: 1 << 0,
	PANIC: 1 << 1,
	RTS:  1 << 2,
	SEND_ERROR: 1 << 3,
	SETTINGS: 1 << 4,
	REMOTE_KEY: 1 << 5,
	LOCAL_KEY: 1 << 6,
	LOCAL_KEY_DECRYPTED: 1 << 7,
	LOCAL_KEY_IDENTIFIED: 1 << 8,
	LOCAL_KEY_GENERATE: 1 << 9,
	PASSPHRASE_ACTIVE: 1 << 10,
	PASSPHRASE_FAIL: 1 << 11,
	ACK_MESSAGE: 1 << 12,
	ENC_MESSAGE: 1 << 13,
	ACK_PUBKEY: 1 << 14,
	ENC_PUBKEY: 1 << 15,
	ACK_COUNTER: 1 << 16,
	ENC_COUNTER: 1 << 17,
	HELP: 1 << 18,
	FILE_PROCESS: 1 << 19,
	FILE_ADDED: 1 << 20,
};
const STATE_KEYS = Object.keys(STATE);

let g_passphrase = undefined;
let g_passphrase_use = true;
let g_passphrase_time = 0;
let g_remote_key = undefined;
let g_local_key = undefined;
let g_remote_key_id = '(none)';
let g_remote_key_name = '?';
let g_remote_key_email = undefined;
let g_local_key_id = '(none)';
let g_local_key_name = '?';
let g_local_key_identified = false;
let g_data_endpoint = window.location.href;
let g_state = 0;
let g_helpstate = 0;
let g_counter = undefined;
let g_files = {};
let g_version = '0.1.0';
let g_from = 'no-reply@localhost';
let g_from_name = 'Forro v' + g_version;
