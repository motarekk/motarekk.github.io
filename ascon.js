/*
* Javascript implementation of Ascon, an authenticated cipher and hash function (NIST SP 800-232 standard)
* Algorithms: Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128
* By Mohamed Tarek, aka. motarek
* GitHub: https://github.com/motarekk
* Email: motarek424@gmail.com
* LinkedIn: https://www.linkedin.com/in/mohamed-tarek-159a821ba/
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

// data format: raw or hex
var format = "raw"; 
function data_format(){
    if(format == "raw"){
        format = "hex";
    } else {
        format = "raw";
    }
}

// === Ascon AEAD encryption and decryption ===
function ascon_aead(key, nonce, associateddata, data, operation, variant="Ascon-AEAD128"){
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
    var b = 8;    // intermediate rounds
    var rate = 16;    // bytes
    var plaintext = "";
    var ciphertext = "";
    var tag = "";
    
    // data format: raw or hex
    if(format == "hex"){associateddata = to_unicode(associateddata);}

    S = ascon_initialize(S, rate, a, b, key, nonce);
    ascon_process_associated_data(S, b, rate, associateddata);

    if(operation == "encrypt"){
        if(format == "hex"){data = to_unicode(data);} // data format: raw or hex
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

// Ascon hash/xof
function ascon_hash(message, hashlength=32, variant="Ascon-Hash256", customization=""){
    /*
    * customization: a bytes object of at most 256 bytes specifying the customization string (only for Ascon-CXOF128)
    */
    versions = {"Ascon-Hash256": 2,
        "Ascon-XOF128": 3,
        "Ascon-CXOF128": 4};

    // checks
    if(variant == "Ascon-Hash256"){
        if(hashlength != 32){
            return "in Ascon-Hash256, hash length must be 32 bytes.";
        } 
    }
    if(variant == "Ascon-CXOF128"){
        if(customization.length > 256){
            return "in Ascon-CXOF128, customization string can be at most 256 bytes.";
        }
    } else {
        if(customization.length != 0){
            return "customization string is only for Ascon-CXOF128.";
        }
    }

    // parameters
    var S = [0, 0, 0, 0, 0];    // state raws
    var rate = 8        // bytes
    var a = 12;     // intial & final rounds
    var b = 12;      // intermediate rounds
    var taglen = 0;
    var customize = false;

    if(variant == "Ascon-Hash256"){
        taglen = 256;
    }
    if (variant == "Ascon-CXOF128"){
        customize = true;
    }

    // data format: raw or hex
    if(format == "hex"){
        message = to_unicode(message);
        customization = to_unicode(customization);
    }

    // Intialization
    iv = int_to_hex(versions[variant], 2) + int_to_hex(0, 2) + int_to_hex((b<<4) + a, 2) + bigEndianToLittleEndian(int_to_hex(taglen, 4)) + int_to_hex(rate, 2) + int_to_hex(0, 4);
    var zeros = int_to_hex(0, 64);
    var S = bytes_to_state(iv+zeros);    
    ascon_permutation(S, 12);

    // Customization
    if(customize){
        var z_padding = "\x01" + zero_bytes(rate - (customization.length % rate) - 1);
        var z_length = to_unicode(bigEndianToLittleEndian(int_to_hex(customization.length*8, 8*2)));
        var z_padded = z_length + customization + z_padding;

        // customization blocks 0,...,m
        for(var block = 0; block < z_padded.length; block += rate){
            S[0] ^= bytes_to_int(z_padded.slice(block, block+rate));
            ascon_permutation(S, 12);
        }
    }

    // Message Processing (Absorbing)
    var m_padding = "\x01" + zero_bytes(rate - (message.length % rate) - 1);
    var m_padded = message + m_padding;

    // message blocks 0,...,n
    for(var block = 0; block < m_padded.length; block += rate){
        S[0] ^= str_to_long(m_padded.slice(block, block+rate));
        ascon_permutation(S, 12);
    }

    // Finalization: Message Squeezing
    var H = "";
    while(H.length < hashlength*2){
        H += bigEndianToLittleEndian(int_to_hex(S[0], rate*2));
        ascon_permutation(S, 12);
    }

    return H.slice(0, hashlength*2);
}

function ascon_initialize(S, rate, a, b, key, nonce) {
    var version = 1;
    var taglen = 128;
    var iv_zeros = "0000";
    var iv = int_to_hex(version, 2) + int_to_hex(0, 2) + int_to_hex((b<<4) + a, 2) + int_to_hex(taglen, 2) + int_to_hex(rate, 4) + iv_zeros;
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
            S[0] ^= str_to_long(ad_padded.slice(block, block+8));

            if(rate == 16){
                S[1] ^= str_to_long(ad_padded.slice(block+8, block+16));
            }
            ascon_permutation(S, b);
        }
    }
    S[4] ^= 9223372036854775808n; // 9223372036854775808n == 1<<63
}

function ascon_process_plaintext(S, b, rate, plaintext) {
    // padding
    var padded_plaintext = pad(plaintext, 8);
    var p_lastlen = plaintext.length % rate;
    var p_zero_bytes = (rate - p_lastlen) - 1;
    var required_len = plaintext.length + p_zero_bytes + 1;

    // absorbtion of plaintext & squeezing of ciphertext
    // processing of first t-1 blocks (all blocks except the last one)
    var ciphertext = []; 
    var blocks = required_len - rate;
    for(var i = 0; i < blocks; i+=rate){
        S[0] ^= str_to_long(padded_plaintext.slice(i, i+8));
        S[1] ^= str_to_long(padded_plaintext.slice(i+8, i+16));
        ciphertext += bigEndianToLittleEndian(int_to_hex(S[0])) + bigEndianToLittleEndian(int_to_hex(S[1]));
        ascon_permutation(S, b);
    }

    // processing of last block t
    S[0] ^= str_to_long(padded_plaintext.slice(blocks, blocks+8));
    S[1] ^= str_to_long(padded_plaintext.slice(blocks+8, blocks+16));
    ciphertext += bigEndianToLittleEndian(int_to_hex(S[0])).slice(0, Math.min(16, p_lastlen*2)) + bigEndianToLittleEndian(int_to_hex(S[1])).slice(0, Math.max(0, p_lastlen*2-16));
    
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
        Ci = [BigInt('0x' + bigEndianToLittleEndian(ciphertext.slice(i*2, i+8*mult))), BigInt('0x' + bigEndianToLittleEndian(ciphertext.slice(i*2+rate, i+8*mult+rate)))];
        mult+=2;
        plaintext += to_unicode(bigEndianToLittleEndian(int_to_hex(S[0] ^ Ci[0])) + bigEndianToLittleEndian(int_to_hex(S[1] ^ Ci[1])));
        S[0] = Ci[0];
        S[1] = Ci[1];
        ascon_permutation(S, b);
    }

    // processing of last block t
    c_padx = zero_bytes(c_lastlen) + "\x01" + zero_bytes(rate-c_lastlen-1);
    c_mask = zero_bytes(c_lastlen) + ff_bytes(rate-c_lastlen);
    Ci = [BigInt('0x' + bigEndianToLittleEndian(ciphertext.slice(blocks*2, blocks*2+16))), BigInt('0x' + bigEndianToLittleEndian(ciphertext.slice(blocks*2+16, blocks*2+32)))];

    plaintext += to_unicode(bigEndianToLittleEndian(int_to_hex(S[0] ^ Ci[0])) + bigEndianToLittleEndian(int_to_hex(S[1] ^ Ci[1]))).slice(0, c_lastlen);

    S[0] = (S[0] & bytes_to_int(c_mask.slice(0, 8))) ^ Ci[0] ^ bytes_to_int(c_padx.slice(0, 8));
    S[1] = (S[1] & bytes_to_int(c_mask.slice(8, 16))) ^ Ci[1] ^ bytes_to_int(c_padx.slice(8, 16));

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
    S[rate/8+0] ^= BigInt('0x' + bigEndianToLittleEndian(key.slice(0, 16)));
    S[rate/8+1] ^= BigInt('0x' + bigEndianToLittleEndian(key.slice(16)));

    ascon_permutation(S, a);

    // step 2: 4th & 5th raws of the state are XORed with the key, and the result will be the tag
    S[3] ^= BigInt('0x' + bigEndianToLittleEndian(key.slice(0, 16)));
    S[4] ^= BigInt('0x' + bigEndianToLittleEndian(key.slice(16)));

    var tag = int_to_hex(S[4]) + int_to_hex(S[3]);
    return bigEndianToLittleEndian(tag);
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
        T = [];
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
function bigEndianToLittleEndian(hex) { // got help from ChatGPT on this
    // Ensure even length
    if (hex.length % 2 !== 0) {
        throw new Error("Hex string length must be even.");
    } else if (hex.length == 0) {
        return "00";
    }

    // Split into bytes (2 characters each)
    const bytes = hex.match(/.{2}/g);

    // Reverse the array
    const reversedBytes = bytes.reverse();

    // Join back into a string
    return reversedBytes.join('');
}

function bytes_to_state(bytes){ // input: hexadecimal bytes
    var state = [];
    for(var w = 0; w < 5; w++){
        state.push(BigInt('0x' + bigEndianToLittleEndian(bytes.slice(16*w, 16*(w+1)))));
    }
    return state;
}

// left shift
function l_shift(number, shift) {
    return BigInt(number) * BigInt(Math.pow(2, shift));
}

function rotr(val, r){
    return (val >> BigInt(r)) | l_shift(val & ((l_shift(1, r))-BigInt(1)), (64-r));
}

function get_random_bytes(num){
    var buf = new Uint8Array(num);
    crypto.getRandomValues(buf);
    buf = bytes_to_hex(buf);
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
        if(bytes[i].toString(16).length % 2 != 0){
            hex.push('0'+bytes[i].toString(16));
        } else {
            hex.push(bytes[i].toString(16));
        }
    }
    return hex;
}
// equivalent to 'to_bytes(8, "big").hex()' in python
function int_to_hex(int, pad=8) {
    var int = int.toString(16);

    while(int.length % pad != 0) {
        int = '0' + int;
    }
    return int;
}
// convert string > ascii > hex > decimal
// equivalent to 'int(b"str".hex(), 16)' in python
function str_to_long(str) {
    var str = bytes_to_hex(to_ascii(str));
    var long = "";
    for(var i = str.length-1; i >= 0; i--){
        long += str[i];
    }
    return BigInt('0x0' + long);
}

// convert big endian to little endian
function bytes_to_int(bytes) {
    var sum = 0n;
    for (var i = 0; i < bytes.length; i++){
        bi = str_to_long(bytes[i]);
        bi = bi << BigInt(i*8);
        sum += bi;
    }
    return sum;
}

function pad(data, rate){
    var d_lastlen = data.length % rate;
    var d_zero_bytes = (rate - d_lastlen) - 1;
    var padding = "\x01";

    for(var i = 0; i < d_zero_bytes; i++){
        padding += "\x00";
    }
    return data + padding;
}

function zero_bytes(n){
    var zb = "";
    for (var i = 0; i < n; i++){
        zb += "\x00";
    }
    return zb;
}

function ff_bytes(n){
    var ffb = "";
    for (var i = 0; i < n; i++){
        ffb += "\xff";
    }
    return ffb;
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
    var ct =  ascon_aead(key, nonce, ad, pt, "encrypt", variant);
    var tag = ct.slice(-32);
    return "ciphertext: " + ct.slice(0, -32) + "\ntag: " + tag;
}

// decryption
function decrypt(key, nonce, ad, ct, variant){
    var pt =  ascon_aead(key, nonce, ad, ct, "decrypt", variant);
    var verification = "";

    if(pt != null){
        verification = "succeeded!";
        // data format: raw or hex
        if(format == "hex"){
            pt = JSON.stringify(bytes_to_hex(to_ascii(pt))).replaceAll(/[",\][]/g,'');
        }
        return "plaintext: " + pt + "\nverification: " + verification;
    } else {
        return "verification failed!";
    }

}

function hash(message, hashlength, variant, customization){
    if(hashlength==''){
        hashlength = 32;
    }
    var H = ascon_hash(message, hashlength, variant, customization);
    return "Tag: " + H;
}

// hall of fame
var hof_flag = false;
var hof ="<p>Thanks to all who reported bugs and contributed to improve this tool.</p><p>______________</p><p>Joshua Holden</p><p>Majid M.Niknam</p><p>______________</p><br>";
function hof_toggle(){
    if(!hof_flag){
        document.getElementById('hof_arrow').classList.remove('rotate-up');
        document.getElementById('hof_arrow').classList.add('rotate-down');
        document.getElementById('hof').innerHTML = hof;
        hof_flag = true;
    } else {
        document.getElementById('hof_arrow').classList.remove('rotate-down');
        document.getElementById('hof_arrow').classList.add('rotate-up');
        document.getElementById('hof').innerHTML = "";
        hof_flag = false;
    }
}

// ctf
var ctf_flag = false;
var ctf = "solve a challenge, reach out to me with the flag, your name get listed in the solvers section<br>you'll find my email in ascon.js file<br>____________<br>";
var challenge_1 = "<br><b>#1</b> <b>challenge name:</b> epic fail<b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;difficulty:</b> can't be easier<br><b>description:</b> \"I am lazy to generate more than one random number. I don't think you can decrypt my message though!\"<br><br><b>givens:</b><br>variant = Ascon-AEAD128<br>associated_data = playascon_ctf<br>nonce = ed7299db65af5fb3a683c17127a6050c<br>encrypted_message = b6f991508141a21cfa31b642aa9109d523cfc6eae7f71b16a19b1d9f202fa75e6aecf23220afae7fb233ec9e91b3b816b1ad<br>tag = 380b99364b6d26af115cab63f2ed2d3a<br>key = well, at least I know this must kept secret!";

function ctf_toggle(){
    if(!ctf_flag){
        document.getElementById('ctf_arrow').classList.remove('rotate-up');
        document.getElementById('ctf_arrow').classList.add('rotate-down');
        document.getElementById('ctf').innerHTML = ctf+challenge_1;
        ctf_flag = true;
    } else {
        document.getElementById('ctf_arrow').classList.remove('rotate-down');
        document.getElementById('ctf_arrow').classList.add('rotate-up');
        document.getElementById('ctf').innerHTML = "";
        ctf_flag = false;
    }
}
