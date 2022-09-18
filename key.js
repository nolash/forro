async function generatePGPKey(pwd) {
	return new Promise(async (whohoo, doh) => {
		let v = await openpgp.generateKey({
			//type: 'ecc',
			//curve: 'secp256k1',
			type: 'rsa',
			userIDs: [{name: "Ola Nordmann", email: "ola@nordmann.no" }],
			passphrase: pwd,
			format: 'armored',
			config: { rejectCurves: new Set() },
		});
		//console.debug('pk ' + v.privateKey );
		//console.debug('pubk ' + v.publicKey );
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
		//console.debug('pubk ' + k.toPublic().armor());
		whohoo(k);
	});
}	
