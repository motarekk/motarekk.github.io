/*
* Javascript implementation of Ascon-128 AEAD
* By Mohamed Tarek, aka. motarek
* GitHub: https://github.com/motarekk
* Email: 0xmohamed.tarek@gmail.com
* LinkedIn: https://www.linkedin.com/in/mohamed-tarek-159a821ba/
* Ascon main steps: initialize > associated data > plaintext/ciphertext > finalization
* key & nonce must be entered in hexadecimal
*/

// supporting non-english languages
var eng = true;
function non_eng(){
    if(eng){
        eng = false;
    } else {
        eng = true;
    }
}

// one function for authenticated encryption & decryption
function ascon_aead(key, nonce, associateddata, data, operation, variant){
    // make sure parameters are within the correct ranges
    if(key.length != 32 | nonce.length != 32){
        return "key & nonce must be 16 bytes";
    }

    // URI-encode plaintext to support non-english texts
    if(!eng){
        data = uri_encode_preserve_special_chars(data);
    }

    // parameters
    var S = [0, 0, 0, 0, 0];    // state raws
    var a = 12;    // intial & final rounds
    var b = 6;    // intermediate rounds
    var rate = 8;    // bytes
    var plaintext = "";
    var ciphertext = "";
    var tag = "";
    
    if(variant == "Ascon-128a"){
        b = 8;
        rate = 16;
    } 

    S = ascon_initialize(S, rate, a, b, key, nonce);
    ascon_process_associated_data(S, b, rate, associateddata);

    if(operation == "encrypt"){
        ciphertext = ascon_process_plaintext(S, b, rate, data);
        tag = ascon_finalize(S, rate, a, key);
        // output = ciphertext (same size as plaintext) + tag (128-bits)
        return ciphertext + tag;
    } else {
        plaintext = ascon_process_ciphertext(S, b, rate, data.slice(0, -32)); // exclude the tag
        tag = ascon_finalize(S, rate, a, key);
        // output plaintext
        if(tag == data.slice(-32)) { // verification
            return plaintext;
        } else {
            return null;
        }
    }
}

function ascon_initialize(S, rate, a, b, key, nonce) {
    var iv_zeros = "00000000";
    var iv = int_to_hex(bytes_to_hex([128])+bytes_to_hex([rate*8])+"0"+bytes_to_hex([a])+bytes_to_hex(["0"+b])+iv_zeros);
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
    return S;
}

function ascon_process_associated_data(S, b, rate, associateddata) {
    // URI-encode plaintext to support non-english texts
    if(!eng){
        associateddata = uri_encode_preserve_special_chars(associateddata);
    }
    
    if (associateddata.length > 0) {
        // padding
        var ad_padded = pad(associateddata, rate);

        for(var block = 0; block < ad_padded.length; block+=rate){
            S[0] ^= str_to_long(ad_padded.slice(block,block+8));

            if(rate == 16){
                S[1] ^= str_to_long(ad_padded.slice(block+8, block+16))
            }
            ascon_permutation(S, b);
        }
        }
        S[4] ^= BigInt(1);
    }

function ascon_process_plaintext(S, b, rate, plaintext) {
    // padding
    var padded_plaintext = pad(plaintext, rate);
    var p_lastlen = plaintext.length % rate;
    var p_zero_bytes = (rate - p_lastlen) - 1;
    var required_len = plaintext.length + p_zero_bytes + 1;
    
    // absorbtion of plaintext & squeezing of ciphertext
    // processing of first t-1 blocks (all blocks except the last one)
    var ciphertext = []; 
    var blocks = required_len - rate;
    for(var i = 0; i < blocks; i+=rate){
        if(rate == 8){
            S[0] ^= str_to_long(padded_plaintext.slice(i, i+8));
            ciphertext += int_to_hex(S[0]);
        } else if(rate == 16){
            S[0] ^= str_to_long(padded_plaintext.slice(i, i+8));
            S[1] ^= str_to_long(padded_plaintext.slice(i+8, i+16));
            ciphertext += int_to_hex(S[0]) + int_to_hex(S[1]);
        }
        ascon_permutation(S, b);
    }

    // processing of last block t
    if(rate == 8){
        S[0] ^= str_to_long(pad(plaintext.slice(blocks), rate));
        ciphertext += int_to_hex(S[0]).slice(0, p_lastlen*2);
    } else if(rate == 16){
        S[0] ^= str_to_long(padded_plaintext.slice(blocks, blocks+8));
        S[1] ^= str_to_long(padded_plaintext.slice(blocks+8));
        ciphertext += int_to_hex(S[0]).slice(0, Math.min(16, p_lastlen*2)) + int_to_hex(S[1]).slice(0, Math.max(0, p_lastlen*2-16));
    }
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
        if(rate == 8){
            Ci = BigInt('0x' + ciphertext.slice(i*2, i+rate*mult));
            mult+=1;
            plaintext += to_unicode(int_to_hex(S[0] ^ Ci)); 
            S[0] = Ci;
        } else if(rate == 16){
            Ci = [BigInt('0x' + ciphertext.slice(i*2, i+8*mult)), BigInt('0x' + ciphertext.slice(i*2+rate, i+8*mult+rate))];
            mult+=2;
            plaintext += to_unicode(int_to_hex(S[0] ^ Ci[0]) + int_to_hex(S[1] ^ Ci[1]));
            S[0] = Ci[0];
            S[1] = Ci[1];
        }
        ascon_permutation(S, b);
    }

    // processing of last block t
    if(rate == 8){
        var c_last = pad_ciphertext(ciphertext.slice(blocks*2), rate);
        plaintext += to_unicode(int_to_hex(S[0] ^ c_last)).slice(0, c_lastlen); 
        var padded_plaintext = pad(plaintext.slice(blocks), rate);
        S[0] ^= str_to_long(padded_plaintext);
    } else if(rate == 16){
        if(c_lastlen < 8){
            var c_last = [pad_ciphertext(ciphertext.slice(blocks*2, blocks*2+rate), 8), pad_ciphertext(ciphertext.slice(blocks*2+rate), 8)];
            plaintext += to_unicode(int_to_hex(S[0] ^ c_last[0]) + int_to_hex(S[1] ^ c_last[1])).slice(0, c_lastlen); 
            S[0] ^= str_to_long(pad(plaintext.slice(blocks), 8));
        } else{
            var c_last = [pad_ciphertext_(ciphertext.slice(blocks*2, blocks*2+rate), 8), pad_ciphertext_(ciphertext.slice(blocks*2+rate), 8)];
            plaintext += to_unicode(int_to_hex(S[0] ^ c_last[0]) + int_to_hex(S[1] ^ c_last[1])).slice(0, c_lastlen); 
            S[0] ^= str_to_long(pad(plaintext.slice(blocks, blocks+8), 8));
            S[1] ^= str_to_long(pad(plaintext.slice(blocks+8),8)) 
        }
    }

    // URI-decode plaintext if it's encoded to support non-english texts
    if(!eng){
        try{plaintext = decodeURIComponent(plaintext);
        } catch(err){
            return null;
        }
    }
    return plaintext;
}

function ascon_finalize(S, rate, a, key) {
    // check the key length is as required
    if(key.length != 32){
        return "key must be 16 bytes";
    }

    // step 1: XOR the key with the state, then permute
    S[rate/8+0] ^= BigInt('0x' + key.slice(0, 16));
    S[rate/8+1] ^= BigInt('0x' + key.slice(16));

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
    buf = bytes_to_hex_(buf);
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
    var padding = "\x80";

    if(data !="" && data.length % rate == 0){
        padding = "";
    } else {
        for(var i = 0; i < d_zero_bytes; i++){
            padding += "\x00";
        }
    }
    return data + padding;
}

function pad_ciphertext(data, rate){
    var d_lastlen = (data.length/2) % rate;
    var d_zero_bytes = rate - d_lastlen;
    var padding = ''.padEnd(d_zero_bytes*2, '0');
    if(data == ""){
        data = "0";
    }
    return BigInt('0x' + (data + bytes_to_hex(padding)).replace(/,/g, ''));
}

// preserve special characters while URI-encoding
function uri_encode_preserve_special_chars(text){
    return encodeURIComponent(text).replaceAll('%0A', '\n').replaceAll('%20',' ').replaceAll('%2B','+').replaceAll('%3D', '=').replaceAll('%2F','/').replaceAll('%5C','\\').replaceAll('%26','&').replaceAll('%5E','^').replaceAll('%24','$').replaceAll('%23','#').replaceAll('%40','@').replaceAll('%60','`').replaceAll('%3C','<').replaceAll('%3E','>').replaceAll('%22','\"').replaceAll('%7B', '{').replaceAll('%7D','}').replaceAll('%5B','[').replaceAll('%5D',']').replaceAll('%7C','|').replaceAll('%3F','?').replaceAll('%3B',';').replaceAll('%3A',':').replaceAll('%2C',','); 
}

/*
=== end of helper functions ===
*/

// encryption
function encrypt(key, nonce, ad, pt, variant){
    var key = key;
    var nonce = nonce;
    var pt = pt;
    var ad = ad;
    var ct =  ascon_aead(key, nonce, ad, pt, "encrypt", variant);
    var tag = ct.slice(-32);
    return "ciphertext: " + ct.slice(0, -32) + "\ntag: " + tag;
}

// decryption
function decrypt(key, nonce, ad, ct, variant){
    var key = key;
    var nonce = nonce;
    var ct = ct;
    var ad = ad;
    var pt =  ascon_aead(key, nonce, ad, ct, "decrypt", variant);
    var verification = "";

    if(pt != null){
        verification = "succeeded!";
        return "plaintext: " + pt + "\nverification: " + verification;
    } else {
        return "verification failed!";
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
