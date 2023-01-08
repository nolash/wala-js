async function wala_demo_run() {
	const pwd = document.getElementById('wala_password').value;
	if (!await wala_setPwd(pwd)) {
		throw 'eek cant decrypt key';
	}

	const k_foo = await _WALA.store.put_mutable('foo', 'foo', 'foo.txt', 'text/plain');
	const k_bar = await _WALA.store.put('bar', 'foo.txt', 'text/plain');
	console.debug(await _WALA.store.get(k_foo));
	console.debug(await _WALA.store.get(k_bar));
}
