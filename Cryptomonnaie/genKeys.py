from random import randint
import math, time, resource, psutil, hashlib, json, random
import numpy as np
from ecdsa import SigningKey, SECP256k1, VerifyingKey
def privateKey_gen():
    randomnb = 0 
    maxnb = 2**256
    randomnb = randint(1,maxnb)
    return randomnb

def sizeof(r):
    bytes_length = math.ceil(math.log2(r + 1) / 8)
    return bytes_length

def mpz_to_bytes(value):
    hex_rep = hex(value)
    hex_str = hex_rep[2:]
    if len(hex_str) %2 != 0 :
        hex_str = '0' + hex_str
    return hex_str

def compress(randomnumber): 
    bytes_length = sizeof(randomnumber) 
    randomnumber_bytes = randomnumber.to_bytes(bytes_length, 'big') + 0x01.to_bytes(1, 'big')
    compressed_privateKey = int.from_bytes(randomnumber_bytes, 'big')
    return compressed_privateKey

def get_publicKey_points(privateKey):
    bytes_length = (sizeof(privateKey))
    if bytes_length == 33:
        privkey = int.from_bytes(privateKey.to_bytes(33, 'big')[:32], 'big')
        signing_key = SigningKey.from_secret_exponent(privkey, curve=SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        return verifying_key.pubkey.point.x(), verifying_key.pubkey.point.y()

def get_publicKey(x,y):
    if y%2:
        publicKey = mpz_to_bytes(0x03) + mpz_to_bytes(x)
    else:
        publicKey = mpz_to_bytes(0x02) + mpz_to_bytes(x)
    return publicKey


def base58_from_int(randomnumber):
    sympolbase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    encodebase58 = []
    base = 58
    while randomnumber > 0 : 
        randomnumber, reste = divmod(randomnumber, base)
        encodebase58.append(sympolbase58[reste])
    privateKeyConcatened = ''.join(encodebase58[::-1])
    return privateKeyConcatened

def int_from_base58(base58_string):
    symbol_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base = 58
    
    def decode_char(char):
        return symbol_base58.index(char)

    base58_list = list(base58_string)[::-1]
    result = sum(decode_char(char) * (base**index) for index, char in enumerate(base58_list))   
    return result

def base58_from_bytes(randomnumber):
    sympolbase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    encodebase58 = []
    base = 58
    rd_in_bytes = int.from_bytes(randomnumber, byteorder='big')
    while rd_in_bytes > 0 : 
        rd_in_bytes, reste = divmod(rd_in_bytes, base)
        encodebase58.append(sympolbase58[reste])
    privateKeyConcatened = ''.join(encodebase58[::-1])
    return privateKeyConcatened

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    ripemded = hashlib.new('ripemd160')
    ripemded.update(data)
    return ripemded.digest()

def pk_to_address(publicKey):
    encoded = publicKey.encode()
    pksha256ed = sha256(encoded)
    ripemd160ed = ripemd160(pksha256ed)
    ripe_version = b'\x00' + ripemd160ed
    doubleSha = sha256(sha256(ripe_version))
    fourFirstBytes = doubleSha[:4]
    _sum = ripe_version + fourFirstBytes
    address = base58_from_bytes(_sum)
    return address

def generate_keys_address():
    int_private_key = privateKey_gen()
    privateKey = base58_from_int(int_private_key)
    compressed = compress(int_private_key)
    (x,y) = get_publicKey_points(compressed)
    publicKey = get_publicKey(x,y)
    address = pk_to_address(publicKey)
    list_address = [privateKey, publicKey, address]
    return list_address

def list_address():
    liste_all= []
    list_private = []
    list_public = []
    list_adress = []
    i = 0
    while i<3:
        addresses = generate_keys_address()
        liste_all.append(addresses)
        privateKey = liste_all[0][0]
        list_private.append(privateKey)
        publicKey = liste_all[0][1]
        list_public.append(publicKey)
        adress = liste_all[0][2]
        list_adress.append(adress)
        liste_all = []
        i += 1
    return list_private, list_public, list_adress

def create_json_transaction():
    value =3
    l= 5.0
    rdm = round(np.random.exponential(scale=1/l), 3)
    fee = (min(rdm, 2)/100)*value
    value_output = value - fee
    nb_inputs = 1
    nb_outputs = 1
    input = inputs(value, nb_inputs)
    output = outputs(value_output, nb_outputs)
    json_transaction = {
        "  INPUTS  ": input,
        "  OUTPUTS  ": output,
        "fee": fee,
    }
    return json.dumps(json_transaction, indent=2)

def get_address(list):
    address = list[0][0]
    return address

def inputs(value, nb_address):
    list_input = []
    i = 0
    for i in range(nb_address) :
        list_address = generate_keys_address()
        address = list_address[2]
        sk = list_address[0]
        int_sk = int_from_base58(sk)
        pk = list_address[1]
        pkscript = pkscript_hash()
        signature = generate_signature(int_sk, pkscript)
        json_inputs = {
         "pkscript": '001441b089e98dc4c29ac3c1950acfe7ba3a06b4cf01',
         "value": value,
         "address": address,
         "signature": signature,
         "publicK": pk
        }
        transac = json.dumps(json_inputs, indent=2)
        list_input.append(transac)
        i+=1
    return list_input


def outputs(value,nb_address):
    list_output = []
    i = 0
    for i in range(nb_address) :
        list_address = generate_keys_address()
        address = list_address[2]
        json_outputs = {
          "pkscript": '001441b089e98dc4c29ac3c1950acfe7ba3a06b4cf01',
          "value": value,
          "address": address,
        }
        transac = json.dumps(json_outputs, indent=2)
        list_output.append(transac)
        i+=1
    return list_output


def measure_json_file(json):
    sizeInBytes = len(str(json)) 
    return sizeInBytes

def json_to_binary(json):
    bynary_json = msgpack.packb(json)
    return bynary_json

def pkscript_hash():
    pk_script = '001441b089e98dc4c29ac3c1950acfe7ba3a06b4cf01'
    pkscript_hash = hashlib.sha256(pk_script.encode()).digest()
    return pkscript_hash


def generate_signature(private_key, message_hash):
    signing_key = SigningKey.from_string(bytes.fromhex(hex(private_key)[2:]), curve=SECP256k1)
    signature = signing_key.sign(message_hash)
    signature_hex = signature.hex()
    return signature_hex

def verify_signature(public_key, signature, message_hash):
    vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
    return vk.verify(bytes.fromhex(signature), message_hash)

def measure_size():
    i = 0
    total = 0
    for i in range(10):
        json = create_json_transaction()
        total += measure_json_file(json)
        print(measure_json_file(json))
        i+=1
    total = total/10
    return total

measure_size()
