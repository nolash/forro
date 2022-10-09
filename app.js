// Thanks to:
// https://stackoverflow.com/questions/40031688/javascript-arraybuffer-to-hex
function buf2hex(buffer) { // buffer is an ArrayBuffer
	  return [...new Uint8Array(buffer)]
	      .map(x => x.toString(16).padStart(2, '0'))
	      .join('');
}

function msg_identifier() {
	return 'msg' + g_counter;
}

function pubkey_identifier() {
	return PUBKEY_PFX + g_remote_key.getFingerprint();
}

function counter_identifier() {
	return 'msgidx';
}

function debugState(state) {
	let s = '';
	for (let i = 0; i < STATE_KEYS.length; i++) {
		const v = 1 << i;
		if (checkState(state, v)) {
			const k = STATE_KEYS[i];
			if (s.length > 0) {
				s += ', ';
			}
			s += k;
		}
	}
	return s;
};

function checkState(bit_check, bit_field) {
	if (bit_field != 0 && !bit_field) {
		bit_field = g_state;
	}
	return (bit_check & bit_field) > 0;
};

async function loadSettings() {
	let rs = await fetch(window.location.href + '/settings.json', {
		method: 'GET',
	});
	if (!rs.ok) {
		stateChange('could not load settings');
		throw('could not load settings');
	}
	return await rs.json();
}

function getEffectiveName(k) {
	let kl = k.toPacketList();
	let klf = kl.filterByTag(openpgp.enums.packet.userID);
	if (klf.length > 1) {
		stateChange('local key has been identified', STATE["LOCAL_KEY_IDENTIFIED"]);
		g_local_key_identified = true;
	}
	return klf[klf.length-1].name;
}

async function unlockLocalKey(pwd) {
	let state = [];
	try {
		g_local_key = await getKey(pwd);
		state.push(STATE['LOCAL_KEY']);
	} catch(e) {
		stateChange('could not unlock key (passphrase: ' + (pwd !== undefined) + '). Reason: ' + e);
		return false;
	}
	const decrypted = g_local_key.isDecrypted()
	if (decrypted) {
		state.push(STATE['LOCAL_KEY_DECRYPTED']);
	}

	stateChange('found key ' + g_local_key.getKeyID().toHex() + ' (decrypted: ' + decrypted + ')', state);
	return decrypted;
}

async function applyLocalKey() {
	g_local_key_id = g_local_key.getKeyID().toHex();
	g_local_key_name = getEffectiveName(g_local_key);
	
	stateChange('load counter');
	let c = localStorage.getItem('msg-count');
	if (c == null) {
		g_counter = 0;
	} else {
		g_counter = parseInt(c);
	}
	stateChange('ready to send', STATE['RTS']);
}

async function setUp() {
	let settings = await loadSettings();
	if (settings.dev) {
		stateChange("devmode on", STATE.DEV);
	}
	if (settings.help) {
		stateChange("helpmode on", STATE.HELP);
	}

	if (settings.data_endpoint !== undefined) {
		g_data_endpoint = settings.data_endpoint;
		stateChange('updated data endpoint to ' + settings.data_endpoint);
	}

	stateChange('loaded settings', STATE['SETTINGS']);
	let r = await fetch(settings.remote_pubkey_url);
	let remote_key_src = await r.text();
	let remote_key = await openpgp.readKey({
		armoredKey: remote_key_src,
	});
	g_remote_key = remote_key;
	g_remote_key_id = g_remote_key.getKeyID().toHex();
	g_remote_key.getPrimaryUser().then((v) => {
		g_remote_key_name = v.user.userID.name;
		g_remote_key_email = v.user.userID.email;
		stateChange('loaded remote encryption key', STATE['REMOTE_KEY']);
	});
}

async function stateChange(s, set_states, rst_states) {
	if (!set_states) {
		set_states = [];
	} else if (!Array.isArray(set_states)) {
		set_states = [set_states];
	}
	if (!rst_states) {
		rst_states = [];
	} else if (!Array.isArray(rst_states)) {
		rst_states = [rst_states];
	}
	let new_state = g_state;
	for (let i = 0; i < set_states.length; i++) {
		let state = parseInt(set_states[i]);
		new_state |= state;
	}
	for (let i = 0; i < rst_states.length; i++) {
		let state = parseInt(set_states[i]);
		new_state = new_state & (0xffffffff & ~rst_states[i]);
	}
	old_state = g_state;
	g_state = new_state;

	const ev = new CustomEvent('messagestatechange', {
		bubbles: true,
		cancelable: false,
		composed: true,
		detail: {
			s: s,
			c: g_counter,
			kr: g_remote_key_id,
			nr: g_remote_key_name,
			kl: g_local_key_id,
			nl: g_local_key_name,
			old_state: old_state,
			state: new_state,
		},
	});
	window.dispatchEvent(ev);
}

async function tryDispatch(s, name, email, files) {
	stateChange('starting dispatch', undefined, [STATE['RTS'], STATE['SEND_ERROR']]);
	console.debug('files', Object.keys(files));
	let r = undefined;
	try {
		r = await dispatch(s, name, email, files)
		stateChange('ready to send again', STATE['RTS']);
	} catch(e) {
		console.error(e);
		stateChange('send fail: ' + e, STATE['SEND_ERROR']);
		r = 'failed';
	}
	return r;
}

function getPassphrase() {
	return g_passphrase;
}

async function tryIdentify(name, email) {
	if (g_local_key_identified) {
		return false;
	}
	g_local_key = await identify(g_local_key, name, email, getPassphrase());
	g_local_key_name = getEffectiveName(g_local_key);
	await stateChange('apply name change: ' + g_local_key_name);
	console.debug('updated public key', g_local_key.toPublic().armor());
	g_local_key_identified = true;
}

async function dispatch(s, name, email, files) {
	if (name) {
		if (!validateEmail(email)) {
			throw 'invalid email: ' + email;
		}
		await tryIdentify(name, email);
	}

	const pubkey = g_local_key.toPublic();
	const payload = await buildMessage(s, files, pubkey);

	let pfx = msg_identifier();
	let pfx_pub = pubkey_identifier(); 
	let pfx_count = counter_identifier();

	stateChange('sign and encrypt message ' + g_counter);
	const sha_raw = new jsSHA("SHA-256", "TEXT", { encoding: "UTF8" });
	sha_raw.update(s);
	const digest = sha_raw.getHash("HEX");
	console.debug('digest for unencrypted message:', digest);

	// this is done twice, improve
	const rcpt_pubkey_verify = await generatePointer(g_local_key, pfx_pub);
	console.debug('pointer for pubkey', rcpt_pubkey_verify);

	const msg_sig = await signMessage(payload);
	stateChange([g_counter, digest], STATE['SIG_MESSAGE']);

	const msg = await openpgp.createMessage({
		text: payload,
	});
	let r_enc = await encryptMessage(msg, pfx);
	stateChange([g_counter, digest, r_enc.rcpt], STATE['ENC_MESSAGE']);
	let rcpt = await dispatchToEndpoint(r_enc, pfx, true);
	stateChange([g_counter, rcpt], STATE['ACK_MESSAGE']);

	let r_count = await encryptCounter(g_counter, pfx_count);
	g_files = {};
	stateChange([g_counter, r_count.rcpt], STATE['ENC_COUNTER'], [
		STATE.ACK_MESSAGE,
		STATE.ENC_MESSAGE,
	]);
	let rcpt_count = await dispatchToEndpoint(r_count, pfx_count);
	stateChange([g_counter, rcpt_count], STATE['ACK_COUNTER']);

	g_counter += 1;

	localStorage.setItem('msg-count', g_counter);

	//const r_enc_pub = await encryptPublicKey(g_local_key, pfx_pub);
//	stateChange([rcpt_pubkey_verify, r_enc_pub.rcpt], STATE['ENC_PUBKEY'], [
//		STATE.ACK_COUNTER,
//		STATE.ENC_COUNTER,
//	]);
//	let rcpt_pubkey = await dispatchToEndpoint(r_enc_pub, pfx_pub);
//	stateChange(rcpt_pubkey, STATE['ACK_PUBKEY']);

//	stateChange('dispatch complete. next message is ' + g_counter, undefined, [
//		STATE.ACK_PUBKEY,
//		STATE.ENC_PUBKEY,
//	]);

	stateChange('dispatch complete. next message is ' + g_counter, undefined, [
		STATE.ACK_PUBKEY,
		STATE.ENC_PUBKEY,
		STATE.ACK_COUNTER,
		STATE.ENC_COUNTER,
	]);
	return rcpt;
}

async function signMessage(payload) {
	const msg = await openpgp.createMessage({
		text: payload,
	});
	let msg_sig_inner = await openpgp.sign({
		signingKeys: g_local_key,
		message: msg,
		format: 'binary',
	});

	const msg_sig = await openpgp.createMessage({
		binary: msg_sig_inner,
	});
	return msg_sig;
}

async function encryptCounter(c, pfx) {
	const msg_count = await openpgp.createMessage({
		text: '' + g_counter,
	});

	const enc_count = await openpgp.encrypt({
		encryptionKeys: g_local_key,
		format: 'binary',
		message: msg_count,
	});
	let envelope_count = await openpgp.createMessage({
		binary: enc_count,
	});

	const auth = await generateAuth(g_local_key, envelope_count);

	const rcpt_count_verify = await generatePointer(g_local_key, pfx);

	return {
		msg: enc_count,
		auth: auth,
		rcpt: rcpt_count_verify,
	};

}

async function encryptPublicKey(k, pfx) {
	const pubkey_bin = g_local_key.toPublic().write();
	const msg_pubkey = await openpgp.createMessage({
		binary: pubkey_bin,
	});

	const enc_pubkey = await openpgp.encrypt({
		encryptionKeys: g_remote_key,
		format: 'binary',
		message: msg_pubkey,
	});
	let envelope_pubkey = await openpgp.createMessage({
		binary: enc_pubkey,
	});

	const auth = await generateAuth(g_local_key, envelope_pubkey);

	const rcpt_pubkey_verify = await generatePointer(g_local_key, pfx);

	return {
		msg: enc_pubkey,
		auth: auth,
		rcpt: rcpt_pubkey_verify,
	};
}

async function dispatchToEndpoint(o, pfx, trace) {
	let headers = {
		'Content-Type': 'application/octet-stream',
		'Authorization': 'PUBSIG ' + o.auth,
	};

	if (trace)
		headers['X-Wala-Trace'] = '1';

	let res = await fetch(g_data_endpoint + '/' + pfx, {
		method: 'PUT',
		body: o.msg,
		headers: headers,
	});

	rcpt_remote = await res.text();

	if (o.rcpt) {
		if (rcpt_remote.toLowerCase() != o.rcpt.toLowerCase()) {
			throw "mutable ref mismatch between local and server; " + o.rcpt + " != " + rcpt_remote;
		}
	} else {
		console.warn('have no digest to check server reply against');
	}
	return rcpt_remote;
}

async function encryptMessage(msg, pfx) {
	const enckey_local = await g_local_key.getEncryptionKey();
	const enckey_remote = await g_remote_key.getEncryptionKey();

	const enc = await openpgp.encrypt({
		encryptionKeys: [g_remote_key, g_local_key],
		signingKeys: [g_local_key],
		format: 'binary',
		message: msg,
	});
	
	console.debug('encrypted for keys', enckey_local.getKeyID().toHex(), enckey_remote.getKeyID().toHex());
	let envelope = await openpgp.createMessage({
		binary: enc,
	});
	
	const auth = await generateAuth(g_local_key, envelope);

	const rcpt = await generatePointer(g_local_key, pfx);
	console.debug('digest for encrypted message:', rcpt);
	
	return {
		msg: enc,
		rcpt: rcpt,
		auth: auth,
	};
}

async function createLocalKey(pwd) {
	stateChange('generate new local signing key', STATE["LOCAL_KEY_GENERATE"]);
	const uid = {
		name: generateName(),
		email: 'foo@devnull.holbrook.no',
	};
	g_local_key = await generatePGPKey(pwd, uid);
	stateChange('new local signing key named ' + uid.name, STATE["LOCAL_KEY"], STATE["LOCAL_KEY_GENERATE"]);
}

async function setPwd(pwd) {
	stateChange('attempt password set', undefined, STATE['PASSPHRASE_FAIL']);
	if (!pwd) {
		pwd = undefined;
	}
	if (pwd === undefined) {
		if (g_local_key === undefined) {
			g_passphrase_use = false;
			await createLocalKey();
		}
	} else if (g_local_key === undefined) {
		await createLocalKey(pwd);
	}
	let r = await unlockLocalKey(pwd);
	if (!r) {
		stateChange('key unlock fail', STATE['PASSPHRASE_FAIL']);
		return false;
	}
	if (pwd !== undefined) {
		stateChange('passphrase validated', STATE['PASSPHRASE_ACTIVE']);
	}
	applyLocalKey();
	g_passphrase = pwd;
	g_passphrase_time = Date.now();
	return r;
}

function purgeLocalKey() {
	key_id = g_local_key_id;
	localStorage.removeItem('pgp-key');
	localStorage.removeItem('msg-count');
	g_local_key = undefined;
	g_local_key_id = undefined;
	g_local_key_identified = false;
	g_counter = 0;
	g_passphrase = undefined;
	g_passphrase_time = new Date(0);
	const purgeResetStates =  [
		STATE["LOCAL_KEY"],
		STATE["LOCAL_KEY_DECRYPTED"],
		STATE["LOCAL_KEY_IDENTIFIED"],
		STATE["PASSPHRASE_STORED"],
		STATE["RTS"],
		STATE["SEND_ERROR"],
	];
	stateChange('deleted local key ' + key_id, undefined, purgeResetStates);
	return true;
}

async function fileChange(e) {
	let fileButton = document.getElementById("fileAdder")
	let file = fileButton.files[0];
	stateChange('processing file: ' + file.name, STATE.FILE_PROCESS);
	if (file) {
		let f = new FileReader();
		f.onloadend = (r) => {
			let contents = btoa(r.target.result);
			const sha_raw = new jsSHA("SHA-256", "TEXT", { encoding: "UTF8" });
			sha_raw.update(contents);
			const digest = sha_raw.getHash("HEX");
			g_files[digest] = contents;
			stateChange([digest, file.name], STATE.FILE_ADDED, STATE.FILE_PROCESS);
			stateChange('file added: ' + file.name + ' = ' + digest, undefined, STATE['FILE_ADDED']);
		};
		f.readAsBinaryString(file);
	}
}

async function tryHelpFor(...k) {
	//if (!checkState(STATE.HELP)) {
	//	return;
	//}
	const r = await helpFor(g_helpstate, g_state, k);
	g_helpstate = r.state;
	const ev = new CustomEvent('help', {
		bubbles: true,
		cancelable: false,
		composed: true,
		detail: {
			v: r.v,
		},
	});
	window.dispatchEvent(ev);
}

async function buildMessage(message, files, pubkey) {
	let msg = {
		fromName: 'Forro v' + g_version,
		from: g_from,
		to: g_remote_key_email,
		subject: 'contact form message',
		body: "Please see attachments",
		cids: [],
		attaches: [],
	};
	for (v in files) {
		const data = v.target;
		const attach = {
			name: files[v],
			type: "application/octet-stream",
			base64: g_files[v],
		};
		msg.attaches.push(attach);
	}
	const pubkey_attach = {
		name: "pubkey.asc",
		type: "application/octet-stream",
		raw: pubkey.armor(),
	};
	msg.attaches.push(pubkey_attach);
	const msg_mime = Mime.toMimeTxt(msg);
	console.debug(msg_mime);
	return msg_mime;
}

window.addEventListener('messagestatechange', (v) => {
	state_change = (~v.detail.old_state) & v.detail.state;
	let s = v.detail.s;
	if (Array.isArray(s)) {
		s = '[' + s.join(', ') + ']';
	}
	console.debug('message state change:', [s, v.detail.state, debugState(v.detail.state), state_change, debugState(state_change)]);
});
