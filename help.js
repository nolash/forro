const HELPSTATE = {
	INTRO: 1 << 1,
	WRITEMSG: 1 << 2,
};

function checkHelpSkip(helpstate, content, skip_state) {
	let r = {
		state: helpstate,
		content: [],
	};
	if (!skip_state) {
		skip_state = 0;
	}
	if ((helpstate & skip_state) > 0) {
		return r;
	}
	r.state |= skip_state;
	r.content = content;
	return r;
}

function help_welcome(helpstate) {
	const content = [
		"This is an encrypted contact form.",
		"A secret key is needed to read messages you send here.",
	];
	return checkHelpSkip(helpstate, content, HELPSTATE.INTRO);
}

function help_writemsg(helpstate) {
	const content = [
		"The contents of the message will be signed by you and encrypted for the recipient before it is sent.",
		"Once it is sent, a link to where the message is stored will appear in the 'receipt' field above.",
		"The message cannot be read by anyone but the recipient. <em>That includes you, too</em>. If you want a copy, then make one manually",
	];
	//return checkHelpSkip(helpstate, content, HELPSTATE.WRITEMSG);
	return checkHelpSkip(helpstate, content);
}

function help_identify(helpstate) {
	const content = [
		"Identifying yourself means that the name and email you give will be added to your signature key.",
		"You may write any name and email you want.",
		"Any identifying information will be encrypted, and cannot be read by anyone except the recipient.",
	];
	return checkHelpSkip(helpstate, content);
}


async function helpFor(helpstate, state, k) {
	let help = []

	let fn = window['help_' + k];
	if (fn === undefined) {
		console.warn("no help found for '" + k + "'");
	} else {
		let r = fn.call(null, helpstate);
		helpstate = r.state;
		while (r.content.length > 0) {
			help.push(r.content.shift());
		}
	}

	if (state > 0) {
		let state_cpy = state;
		let i = 0;
		while (state_cpy > 0) {
			if ((state_cpy & 1) == 1) {
				let sk = STATE_KEYS[i]	
				fn = window['help_' + k + '_' + sk.toLowerCase() ];
				if (fn !== undefined) {
					console.debug('supplemental help found for ' + k + " with state " + sk);
					let r = fn.call(null, helpstate);
					helpstate = r.state;
					while (r.content.length > 0) {
						help.push(r.content.shift());
					}
				}
			}
			i += 1;
			state_cpy >>= 1;
		}
	}

	return {
		state: helpstate,
		v: help,
	};
}
