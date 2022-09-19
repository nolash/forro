async function generatePGPKey(pwd) {
	return new Promise(async (whohoo, doh) => {
		let v = await openpgp.generateKey({
			//type: 'ecc',
			//curve: 'secp256k1',
			type: 'rsa',
			userIDs: [{name: "Ola Nordmann", email: "ola@nordmann.no" }],
			passphrase: pwd,
			format: 'armored',
			//config: { rejectCurves: new Set() },
		});
		//console.debug('pk ' + v.privateKey );
		console.debug('our public key', v.publicKey );
		localStorage.setItem('pgp-key', v.privateKey);
		let pk = await openpgp.readKey({
			armoredKey: v.privateKey,
		});
		let k = await openpgp.decryptKey({
			privateKey: pk,
			passphrase: pwd,
		});
		whohoo(k);
	});
}

async function getKey(pwd) {
	return new Promise(async (whohoo, doh) => {
		let pk_armor = localStorage.getItem('pgp-key');
		if (pk_armor === null) {
			doh('no key');
			return;
		}
		let pk = await openpgp.readKey({
			armoredKey: pk_armor,
		});
		let k = await openpgp.decryptKey({
			privateKey: pk,
			passphrase: pwd,
		});
		//console.debug('pk ' + k.armor());
		console.debug('our public key', k.toPublic().armor());
		whohoo(k);
	});
}

async function generateAuth(pk, msg) {
	let sig = await openpgp.sign({
		signingKeys: g_local_key,
		message: msg,
		format: 'binary',
		detached: true,
	});
	let pubkey = pk.toPublic().write();
	let pubkey_str = String.fromCharCode.apply(null, pubkey);
	let sig_str = String.fromCharCode.apply(null, sig);

	sig_b = btoa(sig_str);
	pub_b = btoa(pubkey_str);

	return "pgp:" + pub_b + ":" + sig_b;
}

async function generatePointer(pk, pfx) {
	let sha = new jsSHA("SHA-256", "TEXT");
	sha.update(pfx);
	let prefix_digest = sha.getHash("HEX");

	let identity_id = pk.getFingerprint();
	sha = new jsSHA("SHA-256", "HEX");
	sha.update(prefix_digest);
	sha.update(identity_id);
	return sha.getHash("HEX");
}
