async function generatePGPKey() {
	return new Promise(async (whohoo, doh) => {
		console.log(openpgp.generateKey);
		let v = await openpgp.generateKey({
			type: 'ecc',
			curve: 'secp256k1',
			userIDs: [{name: "Ola Nordmann", email: "ola@nordmann.no" }],
			passphrase: 'deadbeef',
			format: 'armored',
			config: { rejectCurves: new Set() },
		});
		console.log('pk ' + v.privateKey );
		console.log('pubk ' + v.publicKey );
		localStorage.setItem('pgp-key', v.privateKey);
		let k = openpgp.readKey({
			armoredKey: v.privateKey,
		});
		whohoo(k);
	});
}

async function getKey(pwd) {
	return new Promise(async (whohoo, doh) => {
		let pk_armor = localStorage.getItem('pgp-key');
		console.log('pk ' + pk_armor);
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
		whohoo(k);
	});
}	
