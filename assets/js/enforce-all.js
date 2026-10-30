(function () {
	'use strict';

	var all = document.getElementById('sigil-enforce-all');
	var list = document.getElementById('sigil-role-list');
	if (!all || !list) {
		return;
	}

	var boxes = Array.prototype.filter.call(list.querySelectorAll('input[type="checkbox"]'), function (box) {
		return box !== all;
	});
	var previous = boxes.map(function (box) {
		return box.checked;
	});

	function sync() {
		boxes.forEach(function (box, i) {
			if (all.checked) {
				box.checked = true;
				box.disabled = true;
			} else {
				box.disabled = false;
				box.checked = previous[i];
			}
		});
	}

	boxes.forEach(function (box, i) {
		box.addEventListener('change', function () {
			previous[i] = box.checked;
		});
	});
	all.addEventListener('change', sync);
	sync();

	// Disabled boxes are not posted, so send the real selection for when "All users" is untoggled later.
	if (list.form) {
		list.form.addEventListener('submit', function () {
			boxes.forEach(function (box, i) {
				box.disabled = false;
				box.checked = previous[i];
			});
		});
	}
})();
