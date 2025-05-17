/*
* Known Answer Tests (KATs) implementation for Ascon (based on genkat.py from pyascon github repo)
* reference: https://github.com/meichlseder/pyascon
*** variant: Ascon-Hash256 ***
*/

function ascon_hash256_KAT(){
    var variant = 'Ascon-Hash256';
    var print_title = `{ Known Answer Tests (KATs) for ${variant} }`;
    console.log(print_title);

    //___ HASH TESTS ___//
    var passed = 0;
    var failed = 0;

    // read Msg & MD from each Count and compare MD with the output MD from ascon.js
    for(var i = 0; i < ascon_hash256_kats.length; i++){
        var msg = to_unicode(ascon_hash256_kats[i].Msg);
        var md = ascon_hash256_kats[i].MD;
        
        try {
            var md_to_test = ascon_hash(msg, 32, variant).toUpperCase();
        } catch (error) {
            console.log(`Error in test case ${ascon_hash256_kats[i].Count}: ${error}`);
        }
        
        if(md == md_to_test){
            passed += 1;
        } else {
            failed += 1;
            console.log(`failed test: ${ascon_hash256_kats[i].Count}`);
        }
    }

    var note = "";
    if(failed > 0){
        note = "\n\nnote: you can view the failed tests in the console";
    }

    var print_hash256_KAT_result = `(Ascon-Hash256):\npassed: ${passed}\nfailed: ${failed}`;
    console.log(print_hash256_KAT_result);

    return `${print_title}\n${print_hash256_KAT_result}${note}`;
}
