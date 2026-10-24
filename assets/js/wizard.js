(function () {
	'use strict';

	// The passkey registers over AJAX and the page does not move on by itself.
	document.addEventListener('sigil:passkey-registered', function () {
		var next = document.getElementById('sigil-wizard-next');
		if (next) {
			next.submit();
		}
	});
})();
