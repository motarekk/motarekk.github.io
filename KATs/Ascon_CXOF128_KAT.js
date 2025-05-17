/*
* Known Answer Tests (KATs) implementation for Ascon (based on genkat.py from pyascon github repo)
* reference: https://github.com/meichlseder/pyascon
*** variant: Ascon-CXOF128 ***
*/

function ascon_cxof128_KAT(){
    var variant = 'Ascon-CXOF128';
    var print_title = `{ Known Answer Tests (KATs) for ${variant} }`;
    console.log(print_title);

    //___ HASH TESTS ___//
    var passed = 0;
    var failed = 0;

    // read Msg & MD from each Count and compare MD with the output MD from ascon.js
    for(var i = 0; i < ascon_cxof128_kats.length; i++){
        var msg = to_unicode(ascon_cxof128_kats[i].Msg);
        var md = ascon_cxof128_kats[i].MD;
        var customization = to_unicode(ascon_cxof128_kats[i].Z);

        try {
            var md_to_test = ascon_hash(msg, 32, variant, customization).toUpperCase();
        } catch (error) {
            console.log(`Error in test case ${ascon_cxof128_kats[i].Count}: ${error}`);
        }

        if(md == md_to_test){
            passed += 1;
        } else {
            failed += 1;
            console.log(`failed test: ${ascon_cxof128_kats[i].Count}`);
        }
    }

    var note = "";
    if(failed > 0){
        note = "\nnote: you can view the failed tests in the console";
    }

    var print_cxof128_KAT_result = `(Ascon-CXOF128):\npassed: ${passed}\nfailed: ${failed}`;
    console.log(print_cxof128_KAT_result);

    return `${print_title}\n${print_cxof128_KAT_result}${note}`;
}
