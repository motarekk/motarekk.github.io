/*
* Known Answer Tests (KATs) implementation for Ascon (based on genkat.py from pyascon github repo)
* reference: https://github.com/meichlseder/pyascon
*** variant: Ascon_AEAD128 ***
*/

function ascon_aead128_KAT(){
    var variant = 'Ascon-AEAD128';
    var key = '000102030405060708090A0B0C0D0E0F';
    var nonce = '000102030405060708090A0B0C0D0E0F';
    var print_title = `{ Known Answer Tests (KATs) for ${variant} }`;
    console.log(print_title);

    //___ ENCRYPTION TESTS ___//
    var operation = "encrypt";
    var passed = 0;
    var failed = 0;

    // read PT & AD from each Count and compare CT with the output CT from ascon.js
    for(var i = 0; i < Ascon_AEAD128_kats.length; i++){
        var pt = to_unicode(Ascon_AEAD128_kats[i].PT);
        var ad = to_unicode(Ascon_AEAD128_kats[i].AD);
        var ct = Ascon_AEAD128_kats[i].CT;

        try {
            var ct_to_test = ascon_aead(key, nonce, ad, pt, operation, variant).toUpperCase();
        } catch (error) {
            console.log(`Error in test case ${Ascon_AEAD128_kats[i].Count}: ${error}`)
        }

        if(ct == ct_to_test){
            passed += 1;
        } else {
            failed += 1;
            console.log(`failed test: ${Ascon_AEAD128_kats[i].Count}`);
        }
    }

    var note = "";
    if(failed > 0){
        note = "\n\nnote: you can view the failed tests in the console";
    }

    var print_encryption_KAT_result = `(encryption):\npassed: ${passed}\nfailed: ${failed}`;
    console.log(print_encryption_KAT_result);

    //___ DECRYPTION TESTS ___//
    operation = "decrypt";
    passed = 0;
    failed = 0;

    // read PT & AD from each Count and compare CT with the output CT from ascon.js
    for(var i = 0; i < Ascon_AEAD128_kats.length; i++){
        var pt = to_unicode(Ascon_AEAD128_kats[i].PT);
        var ad = to_unicode(Ascon_AEAD128_kats[i].AD);
        var ct = Ascon_AEAD128_kats[i].CT;

        try {
            var pt_to_test = ascon_aead(key, nonce, ad, ct.toLowerCase(), operation, variant).toUpperCase();
        } catch (error) {
            console.log(`Error in test case ${Ascon_AEAD128_kats[i].Count}: ${error}`);
        }

        if(pt == pt_to_test){
            passed += 1;
        } else {
            failed += 1;
            console.log(`failed test: ${Ascon_AEAD128_kats[i].Count}`);
        }
    }

    note = "";
    if(failed > 0){
        note = "\n\nnote: you can view the failed tests in the console";
    }

    var print_decryption_KAT_result = `\n(decryption):\npassed: ${passed}\nfailed: ${failed}`;
    console.log(print_decryption_KAT_result);

    return `${print_title}\n${print_encryption_KAT_result}\n${print_decryption_KAT_result}${note}`;
}
