(function () {
	'use strict';

	function cfg() {
		return window.sigilEnrol || {};
	}

	/**
	 * Draw the otpauth URI as a scannable QR, in the browser, with no network
	 * call: the provisioning secret never leaves the page it is already on.
	 *
	 * Rendered as SVG so it stays sharp at any size and needs no canvas.
	 */
	function drawQr(container, text) {
		if (!container || !text) {
			return;
		}

		container.innerHTML = '';

		if (typeof window.qrcode === 'function') {
			try {
				// 0 picks the smallest version that fits. 'M' recovers from about
				// 15% damage, which is the usual choice for screen-scanned codes.
				var qr = window.qrcode(0, 'M');
				qr.addData(text);
				qr.make();

				container.innerHTML = qr.createSvgTag({
					cellSize: 4,
					margin: 8,
					scalable: true,
					alt: cfg().i18n && cfg().i18n.qrAlt ? cfg().i18n.qrAlt : 'Authenticator setup QR code'
				});
				return;
			} catch (e) {
				// Fall through to the manual hint below.
			}
		}

		// The provisioning URI and the secret are already printed above, so the
		// fallback repeats neither; it only says scanning is unavailable.
		var hint = document.createElement('p');
		hint.className = 'description';
		hint.textContent = cfg().i18n && cfg().i18n.qrUnavailable
			? cfg().i18n.qrUnavailable
			: 'Scan is unavailable in this browser view. Enter the secret key manually in your authenticator app.';
		container.appendChild(hint);
	}

	function initTotpQr() {
		var nodes = document.querySelectorAll('.sigil-totp-qr[data-otpauth]');
		for (var i = 0; i < nodes.length; i++) {
			var el = nodes[i];
			var uri = el.getAttribute('data-otpauth') || '';
			drawQr(el, uri);
		}
	}

	document.addEventListener('sigil:passkey-registered', function (event) {
		if (!event.target.closest('#sigil-enrol-form-passkey')) {
			return;
		}
		var url = new window.URL(window.location.href);
		url.searchParams.set('method', 'passkey');
		url.searchParams.set('sigil_status', 'success');
		url.searchParams.set('sigil_code', 'enrolled');
		url.searchParams.delete('sigil_msg');
		window.location.assign(url.href);
	});

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initTotpQr);
	} else {
		initTotpQr();
	}
})();
