const PUBKEY_PFX  = 'pgp.publickey';
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
let g_version = '0.0.8';
let g_from = 'no-reply@localhost';
let g_from_name = 'Forro v' + g_version;
