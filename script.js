// Javascript implementation of Ascon-128 AEAD
// By Mohamed Tarek, aka. motarek
// GitHub: https://github.com/motarekk
// Email: 0xmohamed.tarek@gmail.com
// LinkedIn: https://www.linkedin.com/in/mohamed-tarek-159a821ba/
// Ascon main steps: initialize > associated data > plaintext/ciphertext > finalization
// key & nonce must be entered in hexadecimal

// parameters
var S = [0, 0, 0, 0, 0];    // state raws
var a = 12;    // intial & final rounds
var b = 6;    // intermediate rounds
var rate = 8;    // bytes

function ascon_encrypt(key, nonce, associateddata, plaintext) { // input
    // make sure parameters are within the correct ranges
    if(key.length != 32 | nonce.length != 32){
        return "key & nonce must be 16 bytes";
    }

    // process
    S = ascon_initialize(S, a, key, nonce);
    ascon_process_associated_data(S, b, rate, associateddata);
    var ciphertext = ascon_process_plaintext(S, b, rate, plaintext);
    var tag = ascon_finalize(S, a, key);

    // output = ciphertext (same size as plaintext) + tag (128-bits)
    return ciphertext + tag;
}

function ascon_decrypt(key, nonce, associateddata, ciphertext) { // input
    // make sure parameters are within the correct ranges
    if(key.length != 32 | nonce.length != 32){
        return "key & nonce must be 16 bytes";
    }

    // process
    S = ascon_initialize(S, a, key, nonce);

    ascon_process_associated_data(S, b, rate, associateddata);
    var plaintext = ascon_process_ciphertext(S, b, rate, ciphertext.slice(0, -32)); // exclude the tag
    var tag = ascon_finalize(S, a, key);

    if(tag == ciphertext.slice(-32)) { // verification
        return plaintext;
    } else {
        return null;
    }
}

function ascon_initialize(S, a, key, nonce) {
    var iv = "80400c0600000000";
    var initial_state = iv + key + nonce;
    // filling the state
    S = bytes_to_state(initial_state);

    // intial permutation of the state
    ascon_permutation(S, a);

    // XOR the zero key (padded) with the state
    var zero_key = bytes_to_state(key.padStart(80, '0'));
    for(var i = 0; i < 5; i++) {
        S[i] ^= zero_key[i];
    }

    return S
}

function ascon_process_associated_data(S, b, rate, associateddata) {
    if (associateddata.length > 0) {
        // padding
        var ad_lastlen = associateddata.length % rate;
        var ad_zero_bytes = (rate - ad_lastlen) - 1;
        var required_len = associateddata.length + ad_zero_bytes + 1;

        // absorbtion of associated data
        // XOR padded associated data with the rate, then permute
        for(var i = 0; i < required_len; i+=rate){
            // processing of last block of associated data if the length of ad % rate == 0
            if(ad_lastlen % rate == 0 && i+rate+1 > required_len){
                S[0] ^= pad_last(associateddata.slice(i, i+rate), rate*2)
            }

            S[0] ^= pad(associateddata.slice(i, i+rate), rate)

            ascon_permutation(S, b);
        }
    }

    S[4] ^= BigInt(1);
}

function ascon_process_plaintext(S, b, rate, plaintext) {
    // padding
    var p_lastlen = plaintext.length % rate;
    var p_zero_bytes = (rate - p_lastlen) - 1;
    var required_len = plaintext.length + p_zero_bytes + 1;

    // absorbtion of plaintext & squeezing of ciphertext
    // processing of first t-1 blocks (all blocks except the last one)
    var ciphertext = []; 
    var blocks = required_len - rate;
    for(var i = 0; i < blocks; i+=rate){
        S[0] ^= pad(plaintext.slice(i, i+8), rate)
        ciphertext += int_to_hex(S[0]);
        ascon_permutation(S, b);
    }

    // processing of last block
    var p_last = pad_last(plaintext.slice(blocks), rate)

    // double the padding if pt is empty (required padding: 8 bytes)
    if(plaintext == ''){
        p_last = pad_last(plaintext, rate*2);
    }

    S[0] ^= p_last;
    ciphertext += int_to_hex(S[0]).slice(0, p_lastlen*2)

    return ciphertext;
}

function ascon_process_ciphertext(S, b, rate, ciphertext){ 
    // padding
    var c_lastlen = (ciphertext.length/2) % rate;
    var c_zero_bytes = (rate - c_lastlen) - 1;
    var required_len = (ciphertext.length/2) + c_zero_bytes + 1;

    // absorbtion of ciphertext & squeezing of plaintext
    // processing of first t-1 block (all blocks except the last one)
    var plaintext = [];
    var blocks = required_len - rate;
    var mult = 2;

    for(var i = 0; i < blocks; i+=rate){
        Ci = BigInt('0x' + ciphertext.slice(i*2, i+rate*mult));
        mult+=1;
        plaintext += to_unicode(int_to_hex(S[0] ^ Ci)); 
        S[0] = Ci;
        ascon_permutation(S, b);
    }

    // processing of last block t
    var c_last = pad_ciphertext(ciphertext.slice(blocks*2), rate);
    plaintext += to_unicode(int_to_hex(c_last ^ S[0])).slice(0, c_lastlen); 
    var padded_plaintext = pad_last(plaintext.slice(blocks), rate);
    
    // double the padding if pt is empty (required padding: 8 bytes)
    if(plaintext == ''){
        padded_plaintext = pad_last(plaintext, rate*2);
    }

    S[0] ^= padded_plaintext;

    return plaintext;
}

function ascon_finalize(S, a, key) {
    // check the key length is as required
    if(key.length != 32){
        return "key must be 16 bytes";
    }

    // step 1: XOR the key with the state, then permute
    S[1] ^= BigInt('0x' + key.slice(0, 16));
    S[2] ^= BigInt('0x' + key.slice(16));

    ascon_permutation(S, a);

    // step 2: 4th & 5th raws of the state are xored with the key, and the result will be the tag
    S[3] ^= BigInt('0x' + key.slice(0, 16));
    S[4] ^= BigInt('0x' + key.slice(16));
    var tag = int_to_hex(S[3]) + int_to_hex(S[4]);

    return tag;
}

function ascon_permutation(S, rounds) {
    for (var r = 12-rounds; r < 12; r++){
        // step 1: add round constants
        S[2] ^= BigInt('0xf0' - r*'0x10' + r*'0x1');

        // step 2: substitution layer
        // see sbox instructions at: https://ascon.iaik.tugraz.at/images/sbox_instructions.c
        S[0] ^= S[4];
        S[4] ^= S[3];
        S[2] ^= S[1];
        
        // NOR & ANDing operations
        T = []
        for(var i = 0; i < 5; i++){
            T.push((S[i] ^ BigInt('0xFFFFFFFFFFFFFFFF')) & S[(i+1)%5]);
        }
        for(var i = 0; i < 5; i++){
            S[i] ^= T[(i+1)%5];
        }
        S[1] ^= S[0];
        S[0] ^= S[4];
        S[3] ^= S[2];
        S[2] ^= BigInt('0XFFFFFFFFFFFFFFFF'); // XORing with 1s = NOT operation
    
        // step 3: linear diffusion layer
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28);
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39);
        S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6);
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17);
        S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41);
    }
}

/*
=== helper functions ===
*/
function bytes_to_state(bytes){ // input: hexadecimal bytes
    var state = [];
    for(var w = 0; w < 5; w++){
        state.push(BigInt('0x' + bytes.slice(16*w, 16*(w+1))));
    }
    return state;
}
//left shift
function l_shift(number, shift) {
    return BigInt(number) * BigInt(Math.pow(2, shift));
}

function rotr(val, r){
    return (val >> BigInt(r)) | l_shift(val & ((l_shift(1, r))-BigInt(1)), (64-r));
}

function get_random_bytes(num){
    var buf = new Uint8Array(num);
    crypto.getRandomValues(buf);
    buf = bytes_to_hex_(buf)
    var urandom = "";
    for(var i = 0; i < buf.length; i++){
        urandom += buf[i];
    }

    return urandom;
}
// convert hexadecimal to bytes (equivalent to 'bytes.fromhex' in python)
// used for key, iv & nonce
function hex_to_bytes(hex){
    var bytes = [];
    for(var i = 0; i < hex.length; i+=2){
        bytes.push(parseInt(hex.slice(i, i+2), 16));
    }
    return bytes;
}
// ascii bytes to unicode
function to_unicode(bytes){
    var bytes =  hex_to_bytes(bytes);
    var str = "";
    for(var i = 0; i < bytes.length; i++){
        str += String.fromCharCode(bytes[i]);
    }
    return str;
}
// convert string to ASCII
// used for plaintext & associated data
function to_ascii(str){
    var bytes = [];
    for(var i = 0; i < str.length; i++){
        bytes.push(str[i].charCodeAt(0));
    }
    return bytes;
}

function bytes_to_hex(bytes){
    var hex = [];
    for(var i = 0; i < bytes.length; i++){
        hex.push(bytes[i].toString(16));
    }
    return hex;
}

function bytes_to_hex_(bytes){
    var hex = [];
    for(var i = 0; i < bytes.length; i++){
        if(bytes[i].toString(16).length % 2 != 0){
            hex.push('0'+bytes[i].toString(16));
        } else {
            hex.push(bytes[i].toString(16));
        }
    }
    return hex;
}
// equivalent to 'to_bytes(8, "big").hex()' in python
function int_to_hex(int) {
    var int = int.toString(16);

    while(int.length % 8 != 0) {
        int = '0' + int;
    }

    return int;
}
// convert string > ascii > hex > decimal
// equivalent to 'int("str".hex(), 16)' in python
function str_to_long(str) {
    var str = bytes_to_hex_(to_ascii(str));
    var long = "";
    for(var i = 0; i < str.length; i++){
        long += str[i];
    }

    return BigInt('0x0' + long);
}

function pad(data, rate){
    var d_lastlen = data.length % rate;
    var d_zero_bytes = (rate - d_lastlen) - 1;
    var padding = '80' + ''.padEnd(d_zero_bytes*2, '0');

    if(data.length % rate == 0){
        padding = '80' + ''.padEnd(7*2, '0');
    }

    if(data.length % rate == 0){
        return str_to_long(data);
    } else {
        return BigInt('0x' + (bytes_to_hex_(to_ascii((data))) + bytes_to_hex(padding)).replace(/,/g, ''));
    }
}    

function pad_last(data, rate){
    var d_lastlen = data.length % rate;
    var d_zero_bytes = (rate - d_lastlen) - 1;
    var padding = '80' + ''.padEnd(d_zero_bytes*2, '0');

    if(data.length % rate == 0){
        padding = '80' + ''.padEnd(rate-1*2, '0');
    }

    return BigInt('0x' + (bytes_to_hex_(to_ascii((data))) + bytes_to_hex(padding)).replace(/,/g, ''));
}    

function pad_ciphertext(data, rate){
    var d_lastlen = (data.length/2) % rate;
    var d_zero_bytes = rate - d_lastlen;
    var padding = ''.padEnd(d_zero_bytes*2, '0');

    return BigInt('0x' + ((data) + bytes_to_hex(padding)).replace(/,/g, ''));
}


// encryption
function encrypt(key, nonce, pt, ad){
    var key = key;
    var nonce = nonce;
    var pt = pt;
    var ad = ad;
    var ct =  ascon_encrypt(key, nonce, ad, pt);
    var tag = ct.slice(-32);

    return "ciphertext: " + ct.slice(0, -32) + "\ntag: " + tag;
}

// decryption
function decrypt(key, nonce, ct, ad){
    var key = key;
    var nonce = nonce;
    var ct = ct;
    var ad = ad;
    var pt =  ascon_decrypt(key, nonce, ad, ct);
    var verification = ""

    if(pt != null){
        verification = "succeeded!";
        return "plaintext: " + pt + "\nverification: " + verification;
    } else {
        return "verification failed!"
    }

}

// hall of fame
var flag = false;
var hof ="<p>Thanks to all who reported bugs and contributed to improve this tool.</p><p>______________</p><p>Joshua Holden</p><p>Majid M.Niknam</p><p>______________</p><br>";
function toggle(){
    if(!flag){
        document.getElementById('arrow').classList.remove('rotate-up');
        document.getElementById('arrow').classList.add('rotate-down');
        document.getElementById('hof').innerHTML = hof;
        flag = true;
    } else {
        document.getElementById('arrow').classList.remove('rotate-down');
        document.getElementById('arrow').classList.add('rotate-up');
        document.getElementById('hof').innerHTML = "";
        flag = false;
    }
}
