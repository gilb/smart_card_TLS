--------------
smart card TLS
--------------

Client implementation of TLS in Java Card based on the EAP-TLS code for smart cards from Pascal Urien: http://www.infres.enst.fr/~urien/openeapsmartcard/.
The first commit corresponds to the initial code of Pascal Urien, not updated since 2005, the second commit is my modified code from 2011, with the following implementations:

- remove cypher suite TLS_RSA_WITH_RC4_128_SHA and implementation of TLS_RSA_WITH_AES_128_CBC_SHA
- implementation of the entire TLS Record
- possibility to transmit the password from smart card to server through TLS for authentication on a service
- minor changes: memory management, harden certificate checking, cleanups...
- update RSA 1024 to RSA 2048 for client signature and encryption with server public key

It has been tested with success for authentication on Gmail mobile (lightweight version) with the card G&D SmartCafe 3.2, performances for authentication plus check of emails are about 14 seconds, and few seconds more to check a particular email of average size.
It is designed to be used with the Java bridge of the "OpenEAP smartcard" project: http://www.infres.enst.fr/~urien/openeapsmartcard/SmartHook.html.
In order to load the CA certificate in the card, see: https://github.com/gilb/smart_card_TLS/wiki/.
(To be noted that the card application doesn't have any protections against side channels attacks for the moment ;)
