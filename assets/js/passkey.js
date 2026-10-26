(function () {
	'use strict';

	function cfg() {
		return window.sigilPasskey || {};
	}

	function i18n(key) {
		var map = cfg().i18n || {};
		return map[key] || '';
	}

	function setStatus(root, message) {
		var el = root.querySelector('.sigil-passkey-status');
		if (el) {
			el.textContent = message || '';
		}
	}

	function isSupported() {
		return !!(
			window.PublicKeyCredential &&
			navigator.credentials &&
			typeof navigator.credentials.create === 'function' &&
			typeof navigator.credentials.get === 'function' &&
			window.isSecureContext
		);
	}

	function base64UrlToBuffer(base64url) {
		if (typeof base64url !== 'string') {
			return base64url;
		}
		var padding = '='.repeat((4 - (base64url.length % 4)) % 4);
		var base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
		var raw = window.atob(base64);
		var buffer = new ArrayBuffer(raw.length);
		var view = new Uint8Array(buffer);
		for (var i = 0; i < raw.length; i++) {
			view[i] = raw.charCodeAt(i);
		}
		return buffer;
	}

	function bufferToBase64Url(buffer) {
		var bytes = new Uint8Array(buffer);
		var str = '';
		for (var i = 0; i < bytes.byteLength; i++) {
			str += String.fromCharCode(bytes[i]);
		}
		return window
			.btoa(str)
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/g, '');
	}

	function decodeCredentialIds(list) {
		if (!Array.isArray(list)) {
			return;
		}
		list.forEach(function (item) {
			if (item && typeof item.id === 'string') {
				item.id = base64UrlToBuffer(item.id);
			}
		});
	}

	/**
	 * The server sends the WebAuthn options with every binary field base64url
	 * encoded. Only these fields are binary; everything else stays a string.
	 */
	function decodeOptions(options) {
		var publicKey = options && options.publicKey ? options.publicKey : options;
		if (!publicKey) {
			return null;
		}
		if (typeof publicKey.challenge === 'string') {
			publicKey.challenge = base64UrlToBuffer(publicKey.challenge);
		}
		if (publicKey.user && typeof publicKey.user.id === 'string') {
			publicKey.user.id = base64UrlToBuffer(publicKey.user.id);
		}
		decodeCredentialIds(publicKey.excludeCredentials);
		decodeCredentialIds(publicKey.allowCredentials);
		return publicKey;
	}

	function postForm(action, fields) {
		var body = new window.FormData();
		body.append('action', action);
		body.append('nonce', cfg().nonce || '');
		body.append('user_id', String(cfg().userId || ''));
		Object.keys(fields || {}).forEach(function (key) {
			var val = fields[key];
			if (Array.isArray(val)) {
				body.append(key, JSON.stringify(val));
			} else if (val !== undefined && val !== null) {
				body.append(key, String(val));
			}
		});
		return window.fetch(cfg().ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			body: body
		}).then(function (res) {
			return res.json();
		});
	}

	function register(root, replace) {
		if (!isSupported()) {
			setStatus(root, i18n('unsupported'));
			return;
		}

		setStatus(root, i18n('registering'));

		postForm('sigil_passkey_register_options', { replace: replace })
			.then(function (json) {
				if (!json || !json.success) {
					throw new Error((json && json.data && json.data.message) || i18n('failed'));
				}
				var publicKey = decodeOptions(json.data);
				if (!publicKey) {
					throw new Error(i18n('failed'));
				}
				return navigator.credentials.create({ publicKey: publicKey });
			})
			.then(function (cred) {
				if (!cred || !cred.response) {
					throw new Error(i18n('failed'));
				}
				var labelInput = root.querySelector('#sigil-passkey-label');
				var transports = [];
				if (typeof cred.response.getTransports === 'function') {
					transports = cred.response.getTransports() || [];
				}
				// credProps says whether the device kept a resident key, which is
				// what lets the passkey start a sign-in without a password.
				var props = typeof cred.getClientExtensionResults === 'function'
					? (cred.getClientExtensionResults() || {}).credProps
					: null;
				var discoverable = props && typeof props.rk === 'boolean' ? (props.rk ? '1' : '0') : '';
				return postForm('sigil_passkey_register', {
					clientDataJSON: bufferToBase64Url(cred.response.clientDataJSON),
					attestationObject: bufferToBase64Url(cred.response.attestationObject),
					label: labelInput ? labelInput.value : '',
					transports: transports,
					discoverable: discoverable,
					replace: replace
				});
			})
			.then(function (json) {
				if (!json || !json.success) {
					throw new Error((json && json.data && json.data.message) || i18n('failed'));
				}
				setStatus(root, (json.data && json.data.message) || i18n('registered'));
				root.dispatchEvent(new window.CustomEvent('sigil:passkey-registered', { bubbles: true }));
			})
			.catch(function (err) {
				setStatus(root, (err && err.message) || i18n('failed'));
			});
	}

	/**
	 * The login challenge runs logged out, so the options are embedded in the page
	 * and the assertion rides along with the login form POST.
	 */
	function authenticate(root) {
		if (!isSupported()) {
			setStatus(root, i18n('unsupported'));
			return;
		}

		var publicKey = null;
		try {
			publicKey = decodeOptions(JSON.parse(root.getAttribute('data-options') || 'null'));
		} catch (err) {
			publicKey = null;
		}
		if (!publicKey) {
			setStatus(root, i18n('failed'));
			return;
		}

		setStatus(root, i18n('authenticating'));

		navigator.credentials
			.get({ publicKey: publicKey })
			.then(function (cred) {
				if (!cred || !cred.response) {
					throw new Error(i18n('failed'));
				}
				var hidden = root.querySelector('#sigil-passkey-assertion');
				var form = root.closest('form');
				if (!hidden || !form) {
					throw new Error(i18n('failed'));
				}
				hidden.value = JSON.stringify({
					id: bufferToBase64Url(cred.rawId),
					clientDataJSON: bufferToBase64Url(cred.response.clientDataJSON),
					authenticatorData: bufferToBase64Url(cred.response.authenticatorData),
					signature: bufferToBase64Url(cred.response.signature)
				});
				setStatus(root, i18n('verifying'));
				form.submit();
			})
			.catch(function (err) {
				setStatus(root, (err && err.message) || i18n('failed'));
			});
	}

	function onClick(event) {
		var target = event.target;
		if (!(target instanceof Element)) {
			return;
		}
		var regBtn = target.closest('.sigil-passkey-register');
		if (regBtn) {
			var regRoot = regBtn.closest('.sigil-passkey-enrol') || document;
			register(regRoot, regBtn.getAttribute('data-replace') || '');
			return;
		}
		var authBtn = target.closest('.sigil-passkey-authenticate');
		if (authBtn) {
			var authRoot = authBtn.closest('.sigil-passkey-challenge');
			if (authRoot) {
				authenticate(authRoot);
			}
		}
	}

	document.addEventListener('click', onClick);

	window.sigilWebAuthn = {
		isSupported: isSupported,
		decodeOptions: decodeOptions,
		bufferToBase64Url: bufferToBase64Url
	};
})();
