(function () {
	'use strict';

	var cfg = window.sigilPasswordless || {};
	var webauthn = window.sigilWebAuthn;

	// The autofill request waits in the background for as long as the page is
	// open, and a browser runs one WebAuthn request at a time, so the button has
	// to cancel it before asking for its own.
	var autofill = null;

	function i18n(key) {
		return (cfg.i18n || {})[key] || '';
	}

	function setStatus(root, message) {
		var el = root.querySelector('.sigil-passwordless__status');
		if (el) {
			el.textContent = message || '';
		}
	}

	function fetchCeremony() {
		return window.fetch(cfg.restUrl, { credentials: 'same-origin' }).then(function (res) {
			return res.json().then(function (json) {
				if (!res.ok || !json || !json.ceremony) {
					throw new Error((json && json.message) || i18n('failed'));
				}
				return json;
			});
		});
	}

	function submit(root, ceremony, cred) {
		var form = root.closest('form');
		if (!cred || !cred.response || !form) {
			throw new Error(i18n('failed'));
		}

		root.querySelector('[name="sigil_passwordless_ceremony"]').value = ceremony;
		root.querySelector('[name="sigil_passwordless_assertion"]').value = JSON.stringify({
			id: webauthn.bufferToBase64Url(cred.rawId),
			clientDataJSON: webauthn.bufferToBase64Url(cred.response.clientDataJSON),
			authenticatorData: webauthn.bufferToBase64Url(cred.response.authenticatorData),
			signature: webauthn.bufferToBase64Url(cred.response.signature),
			userHandle: cred.response.userHandle ? webauthn.bufferToBase64Url(cred.response.userHandle) : ''
		});

		// A typed password would send the form down the password path instead.
		var password = form.querySelector('input[type="password"]');
		if (password) {
			password.value = '';
		}

		setStatus(root, i18n('verifying'));
		form.submit();
	}

	function startAutofill(root, username) {
		if (typeof window.PublicKeyCredential.isConditionalMediationAvailable !== 'function') {
			return;
		}

		window.PublicKeyCredential.isConditionalMediationAvailable()
			.then(function (available) {
				if (!available) {
					return;
				}
				username.setAttribute('autocomplete', 'username webauthn');
				return fetchCeremony().then(function (data) {
					autofill = new window.AbortController();
					return navigator.credentials
						.get({
							publicKey: webauthn.decodeOptions(data.options),
							mediation: 'conditional',
							signal: autofill.signal
						})
						.then(function (cred) {
							submit(root, data.ceremony, cred);
						});
				});
			})
			.catch(function () {
				// Cancelled for the button, or nothing picked: the form still
				// works with a password.
			});
	}

	function signIn(root) {
		if (autofill) {
			autofill.abort();
			autofill = null;
		}

		setStatus(root, i18n('authenticating'));

		fetchCeremony()
			.then(function (data) {
				return navigator.credentials
					.get({ publicKey: webauthn.decodeOptions(data.options) })
					.then(function (cred) {
						submit(root, data.ceremony, cred);
					});
			})
			.catch(function (err) {
				setStatus(root, (err && err.message) || i18n('failed'));
			});
	}

	function init() {
		if (!webauthn || !webauthn.isSupported()) {
			return;
		}

		// One autofill request per page, however many login forms it holds.
		var autofillStarted = false;

		document.querySelectorAll('.sigil-passwordless').forEach(function (root) {
			var form = root.closest('form');
			if (!form) {
				return;
			}

			// login_form prints between the password and the submit button; the
			// alternative reads better underneath the form's own submit.
			form.appendChild(root);
			root.hidden = false;

			root.querySelector('.sigil-passwordless__button').addEventListener('click', function () {
				signIn(root);
			});

			var username = form.querySelector('input[name="log"]');
			if (username && !autofillStarted) {
				autofillStarted = true;
				startAutofill(root, username);
			}
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
