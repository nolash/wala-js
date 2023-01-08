const _WALA_STATE = {
	LOAD_SETTINGS: 1 << 0,
	KEY_EXIST: 1 << 1,
	KEY_UNLOCKED: 1 << 2,
	KEY_IDENTIFIED: 1 << 3,
	KEY_READYSIGN: 1 << 4,
	KEY_UNLOCK_FAIL: 1 << 5,
	KEY_PASSPHRASE_ACTIVE: 1 << 6,
	KEY_PASSPHRASE_EMPTY: 1 << 7,
	KEY_GENERATE: 1 << 8,
	STORE_AVAILABLE: 1 << 9,
	READY: 1 << 10,
	PANICKED: 1 << 63,
}
const _WALA_STATE_KEYS = Object.keys(_WALA_STATE);

const _WALA_ERROR = {
	SETTINGS_INVALID: 1 << 0,
	STORE_GET: 1 << 1,
	STORE_PUT: 1 << 2,
}

let _WALA = {
	version: "0.0.1",
	settings: null,
	state: 0,
	lasterr: 0,
	passphrase: undefined,
	passphrase_time: 0,
	key: undefined,
	key_id: undefined,
	key_name: undefined,
};


function wala_err(err, panic) {
	if (err === undefined) {
		_WALA.lasterr = 0;
		return;
	}
	_WALA.lasterr = err;
	if (panic) {
		wala_setState(_WALA.STATE.PANICKED);
		throw('brace, brace, brace');
	}
}


// Thanks to:
// https://stackoverflow.com/questions/40031688/javascript-arraybuffer-to-hex
function buf2hex(buffer) { // buffer is an ArrayBuffer
	  return [...new Uint8Array(buffer)]
	      .map(x => x.toString(16).padStart(2, '0'))
	      .join('');
}

//
// Runtime state section
//
function wala_logStateChange(v) {
	state_change = (~v.detail.old_state) & v.detail.state;
	let s = v.detail.s;
	if (Array.isArray(s)) {
		s = '[' + s.join(', ') + ']';
	}
	console.debug('new state:', [s, v.detail.state, wala_debugState(v.detail.state), state_change, wala_debugState(state_change)]);
}

function wala_checkState(bit_check, bit_field) {
	if (bit_field != 0 && !bit_field) {
		bit_field = _WALA.state;
	}
	return (bit_check & bit_field) > 0;
};

function wala_debugState(state) {
	let s = '';
	for (let i = 0; i < _WALA_STATE_KEYS.length; i++) {
		const v = 1 << i;
		if (wala_checkState(state, v)) {
			const k = _WALA_STATE_KEYS[i];
			if (s.length > 0) {
				s += ', ';
			}
			s += k;
		}
	}
	return s;
};

async function wala_stateChange(s, set_states, rst_states) {
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
	let new_state = _WALA.state;
	for (let i = 0; i < set_states.length; i++) {
		let state = parseInt(set_states[i]);
		new_state |= state;
	}
	for (let i = 0; i < rst_states.length; i++) {
		let state = parseInt(set_states[i]);
		new_state = new_state & (0xffffffff & ~rst_states[i]);
	}
	let old_state = _WALA.state;
	_WALA.state = new_state;

	const ev = new CustomEvent('wala_messagestatechange', {
		bubbles: true,
		cancelable: false,
		composed: true,
		detail: {
			s: s,
			old_state: old_state,
			state: new_state,
		},
	});
	window.dispatchEvent(ev);
}


//
// Keys section
//
// name generator pinched from https://stackoverflow.com/questions/16826200/javascript-silly-name-generator
let name_parts = [
	["Runny", "Buttercup", "Dinky", "Stinky", "Crusty",
	"Greasy","Gidget", "Cheesypoof", "Lumpy", "Wacky", "Tiny", "Flunky",
	"Fluffy", "Zippy", "Doofus", "Gobsmacked", "Slimy", "Grimy", "Salamander",
	"Oily", "Burrito", "Bumpy", "Loopy", "Snotty", "Irving", "Egbert"],

	["Waffer", "Lilly","Rugrat","Sand", "Fuzzy","Kitty",
	 "Puppy", "Snuggles","Rubber", "Stinky", "Lulu", "Lala", "Sparkle", "Glitter",
	 "Silver", "Golden", "Rainbow", "Cloud", "Rain", "Stormy", "Wink", "Sugar",
	 "Twinkle", "Star", "Halo", "Angel"],
	["Snicker", "Buffalo", "Gross", "Bubble", "Sheep",
	 "Corset", "Toilet", "Lizard", "Waffle", "Kumquat", "Burger", "Chimp", "Liver",
	 "Gorilla", "Rhino", "Emu", "Pizza", "Toad", "Gerbil", "Pickle", "Tofu", 
	"Chicken", "Potato", "Hamster", "Lemur", "Vermin"],
	["face", "dip", "nose", "brain", "head", "breath", 
	"pants", "shorts", "lips", "mouth", "muffin", "butt", "bottom", "elbow", 
	"honker", "toes", "buns", "spew", "kisser", "fanny", "squirt", "chunks", 
	"brains", "wit", "juice", "shower"],
];

function wala_generateName() {
	name = '';
	for (let i = 0; i < name_parts.length; i++) {
		if (i > 0 && i < 3) {
			name += ' ';
		}
		const ii = Math.random() * name_parts[i].length;
		name += name_parts[i][Math.floor(ii)];
	}
	return name;
}

function wala_getEffectiveName(k) {
	let kl = k.toPacketList();
	let klf = kl.filterByTag(openpgp.enums.packet.userID);
	if (klf.length > 1) {
		wala_stateChange('local key has been identified', STATE.KEY_IDENTIFIED);
	}
	return klf[klf.length-1].name;
}

async function wala_generateAuth(msg) {
	const pk = _WALA.key;
	let sig = await openpgp.sign({
		signingKeys: _WALA.key,
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

async function wala_generatePointer(pfx) {
	const pk = _WALA.key;
	let sha = new jsSHA("SHA-256", "TEXT");
	sha.update(pfx);
	let prefix_digest = sha.getHash("HEX");

	let identity_id = pk.getFingerprint();
	sha = new jsSHA("SHA-256", "HEX");
	sha.update(prefix_digest);
	sha.update(identity_id);
	return sha.getHash("HEX");
}

async function wala_applyLocalKey() {
	_WALA.key_id = _WALA.key.getKeyID().toHex();
	_WALA.key_name = wala_getEffectiveName(_WALA.key);
	wala_stateChange('local signing key ready', _WALA_STATE.KEY_READYSIGN);
}

async function wala_generatePGPKey(pwd, uid) {
	if (uid === undefined) {
		uid = {
			name: "Ola Nordmann",
			email: "ola@nordmann.no",
		};
	}
	uid.comment = 'Generated by wala/' + _WALA.version + ', openpgpjs/5.5.0';
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
	localStorage.setItem('wala-pgp-key', pk.armor());

	return pk;
}

async function wala_getKey(pwd, encrypted) {
	let pk_armor = localStorage.getItem('wala-pgp-key');
	if (pk_armor === null) {
		throw('no key');
	}
	if (encrypted) {
		return pk_armor;
	}
	let pk = await openpgp.readKey({
		armoredKey: pk_armor,
	});
	console.debug('our public key', pk.toPublic().armor());

	if (pwd !== undefined) {
		const r = await openpgp.decryptKey({
			privateKey: pk,
			passphrase: pwd,
		});
		return r;
	} else {
		return pk;
	}
}

async function wala_unlockLocalKey(pwd) {
	let state = [];
	try {
		_WALA.key = await wala_getKey(pwd);
		state.push(_WALA_STATE.KEY_EXIST);
	} catch(e) {
		wala_stateChange('could not unlock key (passphrase: ' + (pwd !== undefined) + '). Reason: ' + e, _WALA_STATE.KEY_UNLOCK_FAIL);
		return false;
	}
	const decrypted = _WALA.key.isDecrypted()
	if (decrypted) {
		state.push(_WALA_STATE.KEY_UNLOCKED);
	}

	wala_stateChange('found key ' + _WALA.key.getKeyID().toHex() + ' (decrypted: ' + decrypted + ')', state);
	return decrypted;
}

async function wala_createLocalKey(pwd) {
	wala_stateChange('generate new local signing key', _WALA_STATE.KEY_GENERATE);
	const uid = {
		name: wala_generateName(),
		email: 'foo@devnull.holbrook.no',
	};
	_WALA.key = await wala_generatePGPKey(pwd, uid);
	wala_stateChange('new local signing key named ' + uid.name, _WALA_STATE.KEY_EXIST, _WALA_STATE.KEY_GENERATE);
}

async function wala_setPwd(pwd) {
	if (!pwd) {
		pwd = undefined;
	}
	wala_stateChange('attempt password set', undefined, _WALA_STATE.KEY_UNLOCK_FAIL);
	let r = await wala_unlockLocalKey(pwd);
	if (!r) {
		if (pwd === undefined) {
			if (_WALA.key === undefined) {
				wala_stateChange('using empty passphrase', _WALA_STATE.KEY_PASSPHRASE_EMPTY);
				await wala_createLocalKey();
			}
		} else if (_WALA.key === undefined) {
			await wala_createLocalKey(pwd);
		}
		r = await wala_unlockLocalKey(pwd);
	}
	if (!r) {
		wala_stateChange('key unlock fail', _WALA_STATE.KEY_UNLOCK_FAIL); 
		return false;
	}
	if (pwd !== undefined) {
		wala_stateChange('passphrase validated', _WALA_STATE.KEY_PASSPHRASE_ACTIVE);
	}
	wala_applyLocalKey();
	_WALA.passphrase = pwd;
	_WALA.passphrase_time = Date.now();
	return r;
}


//
// Store section
// 
function wala_MemStore() {
	this.pfx = 'wala-store-';
	this.name = 'Wala builtin memstore';
}

wala_MemStore.prototype.put_immutable = async function(v, filename, mimetype) {
	const sha_raw = new jsSHA("SHA-256", "TEXT", { encoding: "UTF8" });
	sha_raw.update(v);
	const digest = sha_raw.getHash("HEX");
	const o = {
		pointer: false,
		filename: filename,
		mimetype: mimetype,
		payload: v,
	};
	const k = this.pfx + digest;
	localStorage.setItem(k, JSON.stringify(o));
	return digest;
}

wala_MemStore.prototype.put = async function(v, filename, mimetype) {
	return this.put_immutable(v, filename, mimetype);
}

wala_MemStore.prototype.put_mutable = async function(pfx, v, filename, mimetype) {
	const ptr = await wala_generatePointer(pfx);
	const digest = await this.put_immutable(v, filename, mimetype);
	const o = {
		pointer: true,
		filename: undefined,
		mimetype: undefined,
		payload: digest,
	};
	const k = this.pfx + ptr;
	localStorage.setItem(k, JSON.stringify(o));
	return ptr;
}

wala_MemStore.prototype.get = async function(k) {
	let j = localStorage.getItem(this.pfx + k);
	let o = JSON.parse(j);
	if (!o.pointer) {
		return o.payload;
	}
	console.debug('resolving pointer ' + k + ' -> ' + o.payload);
	j = localStorage.getItem(this.pfx + o.payload);
	o = JSON.parse(j);
	return o.payload;
}

function wala_HttpStore(endpoint) {
	this.endpoint = endpoint;
	this.name = 'Wala default http backend';
}

wala_HttpStore.prototype.put_immutable = async function(v, filename, mimetype) {
	let headers = {
		'Content-Type': mimetype,
	};
	if (_WALA.dev) {
		headers['X-Wala-Trace'] = '1';
	}
	if (filename !== undefined) {
		headers['X-Filename'] = filename;
	}

	const res = await fetch(this.endpoint + '/', {
		method: 'PUT',
		body: v,
		headers: headers,
	});
	rcpt_remote = await res.text();

	return rcpt_remote;
}

wala_HttpStore.prototype.put = async function(v, filename, mimetype) {
	return this.put_immutable(v, filename, mimetype);
}

wala_HttpStore.prototype.put_mutable = async function(pfx, v, filename, mimetype) {
	const ptr = await wala_generatePointer(pfx);
	//const digest = await this.put_immutable(v, filename, mimetype);
	let envelope = await openpgp.createMessage({
		text: v,
	});
	const auth = await wala_generateAuth(envelope);
	let headers = {
		'Content-Type': mimetype,
		'Authorization': 'PUBSIG ' + auth,
	};
	if (_WALA.dev) {
		headers['X-Wala-Trace'] = '1';
	}
	if (filename !== undefined) {
		headers['X-Filename'] = filename;
	}

	const res = await fetch(this.endpoint + '/' + pfx, {
		method: 'PUT',
		body: v,
		headers: headers,
	});
	rcpt_remote = await res.text();

	return ptr;
}

wala_HttpStore.prototype.get = async function(k) {
	const r = await fetch(this.endpoint + '/' + k);
	if (!r.ok) {
		wala_err(_WALA_ERR.STORE_GET);
		return null;
	}
	return await r.text();

}

//
// Settings section
//
function wala_applySettings(s) {
	_WALA.settings = s;
	console.debug('settings set', _WALA.settings);
}

function wala_applySettingsDev() {
	window.addEventListener('wala_messagestatechange', wala_logStateChange);
}

async function wala_loadSettings() {
	let rs = await fetch('/settings.json', {
		method: 'GET',
	});
	if (!rs.ok) {
		stateChange('could not load settings');
		throw('could not load settings');
	}
	const r = await rs.json();
	wala_applySettings(r);

	if (_WALA.settings.dev) { 
		wala_applySettingsDev();
	}
		
	wala_stateChange('settings loaded', _WALA_STATE.LOAD_SETTINGS);
}

async function wala_setStore(v) {
	_WALA.store = v;
	wala_stateChange('store set: ' + v.name, _WALA_STATE.STORE_AVAILABLE); 
}

//
// Entry point
//
async function wala_init() {
	await wala_loadSettings();
	let store = undefined;
	if (_WALA.settings.data_endpoint) {
		store = new wala_HttpStore(_WALA.settings.data_endpoint);
	} else {
		store = new wala_MemStore();
	}
	await wala_setStore(store);
}

async function wala_initEventListener(ev) {
	if (wala_checkState(_WALA_STATE.LOAD_SETTINGS, ev.state)) {
		if (wala_checkState(_WALA_STATE.STORE_AVAILABLE, ev.state)) {
			window.removeEventListener('wala_messagestatechange', wala_initEventListener);
			wala_stateChange('wala is ready to use', _WALA_STATE.READY);
		}
	}
}

window.addEventListener('wala_messagestatechange', wala_initEventListener);
