async function generatePGPKey(pwd, uid) {
	if (uid === undefined) {
		uid = {
			name: "Ola Nordmann",
			email: "ola@nordmann.no",
		};
	}
	uid.comment = 'Generated by forro/' + g_version + ', openpgpjs/5.5.0';
	return new Promise(async (whohoo, doh) => {
		let v = await openpgp.generateKey({
			//type: 'ecc',
			//curve: 'secp256k1',
			type: 'rsa',
			userIDs: [uid],
			passphrase: pwd,
			format: 'armored',
			//config: { rejectCurves: new Set() },
		});
		console.info('our public key', v.publicKey );
		let pk = await openpgp.readKey({
			armoredKey: v.privateKey,
		});
		localStorage.setItem('pgp-key', pk.armor());

		whohoo(pk);
	});
}

async function getKey(pwd, encrypted) {
	return new Promise(async (whohoo, doh) => {
		let pk_armor = localStorage.getItem('pgp-key');
		if (pk_armor === null) {
			doh('no key');
			return;
		}
		if (encrypted) {
			return whohoo(pk_armor);
		}
		let pk = await openpgp.readKey({
			armoredKey: pk_armor,
		});
		console.debug('our public key', pk.toPublic().armor());

		if (pwd !== undefined) {
			openpgp.decryptKey({
				privateKey: pk,
				passphrase: pwd,
			}).then((pk) => {
				whohoo(pk);
			}).catch((e) => {
				doh(e);
			});
		} else {
			whohoo(pk);
		}
	});
}

function getEncryptedKey() {
	return localStorage.getItem('pgp-key');
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

// robbed from https://www.w3resource.com/javascript/form/email-validation.php
function validateEmail(mail) {
	if (/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(mail)) {
		return true;
	}
	return false;
}

async function identify(pk, name, email, pwd) {
	return new Promise(async (whohoo, doh) => {
		const u = openpgp.UserIDPacket.fromObject({
			name: name,
			email: email,
			comment: 'manual entry on forro/' + g_version + ', openpgp/5.5.0',
		});
		let l = pk.toPacketList();
		l.push(u);

		let pk_new = new openpgp.PrivateKey(l);
		if (pwd !== undefined) {
			pk_new = await openpgp.encryptKey({
				privateKey: pk_new,
				passphrase: pwd,

			});
		}

		localStorage.setItem('pgp-key', pk_new.armor());
		
		if (pwd !== undefined) {
			pk_new = await openpgp.decryptKey({
				privateKey: pk_new,
				passphrase: pwd,
			});
		}

		whohoo(pk_new);
	});
}
