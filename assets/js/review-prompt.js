( function () {
	var notice = document.querySelector( '.sigil-review-prompt' );
	if ( ! notice ) {
		return;
	}

	function send( choice ) {
		var body = new URLSearchParams();
		body.set( 'action', 'sigil_review_prompt' );
		body.set( 'choice', choice );
		body.set( '_wpnonce', notice.dataset.nonce );
		return fetch( notice.dataset.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body } );
	}

	notice.addEventListener( 'click', function ( event ) {
		var link = event.target.closest( '[data-sigil-choice]' );

		if ( link ) {
			// The review link keeps its href: the new tab's request records the answer.
			if ( 'review' === link.dataset.sigilChoice ) {
				notice.remove();
				return;
			}
			event.preventDefault();
			send( link.dataset.sigilChoice );
			notice.remove();
			return;
		}

		if ( event.target.closest( '.notice-dismiss' ) ) {
			send( 'later' );
		}
	} );
}() );
