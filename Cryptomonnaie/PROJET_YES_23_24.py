from random import randint
import math, time, resource, psutil, hashlib, json, random, falcon, re
import numpy as np
import binascii

def pkscript_hash():
    pk_script = '001441b089e98dc4c29ac3c1950acfe7ba3a06b4cf01'
    pkscript_hash = hashlib.sha256(pk_script.encode()).digest()
    return pkscript_hash

def pk_to_address(publicKey):
    pk = str(publicKey)
    encoded = pk.encode()
    pksha256ed = sha256(encoded)
    ripemd160ed = ripemd160(pksha256ed)
    ripe_version = b'\x00' + ripemd160ed
    doubleSha = sha256(sha256(ripe_version))
    fourFirstBytes = doubleSha[:4]
    _sum = ripe_version + fourFirstBytes
    address = base58_from_bytes(_sum)
    return address

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



def inputsq(value, nb_address):
    list_input = []
    i = 0
    for i in range(nb_address) :
        sk = falcon.SecretKey(256)
        pk = falcon.PublicKey(sk) 
        pk_json  = extraire(pk) 
        address = pk_to_address(pk_json)
        pkscript = pkscript_hash()
        signature = sk.sign(pkscript)
        sign_hex = chain_to_bytes(signature)
        json_inputs = {
         "pkscript": '001441b089e98dc4c29ac3c1950acfe7ba3a06b4cf01',
         "value": value,
         "address": address,
         "signature": sign_hex,
         "publicK": pk_json
        }
        transac = json.dumps(json_inputs, indent=2)
        list_input.append(transac)
        i+=1
    return list_input


def outputsq(value,nb_address):
    list_output = []
    i = 0
    for i in range(nb_address) :
        sk = falcon.SecretKey(256)
        pk = falcon.PublicKey(sk) 
        pk_json  = extraire(pk)   
        address = pk_to_address(pk_json)
        json_outputs = {
          "pkscript": '001441b089e98dc4c29ac3c1950acfe7ba3a06b4cf01',
          "value": value,
          "address": address,
        }
        transac = json.dumps(json_outputs, indent=2)
        list_output.append(transac)
        i+=1
    return list_output

def create_json_transaction():
    value =3
    l= 5.0
    rdm = round(np.random.exponential(scale=1/l), 3)
    fee = (min(rdm, 2)/100)*value
    value_output = value - fee
    nb_inputs = 1
    nb_outputs = 1
    input = inputsq(value, nb_inputs)
    output = outputsq(value_output, nb_outputs)
    json_transaction = {
        "  INPUTS  ": input,
        "  OUTPUTS  ": output,
        "fee": fee,
    }
    return json.dumps(json_transaction, indent=2)

def measure_json_file(json):
    sizeInBytes = len(str(json)) 
    return sizeInBytes

def chain_to_bytes(chain):
    hexadecimal = binascii.hexlify(chain).decode('utf-8')
    return hexadecimal

def to_hex(entier):
    caracteres_hex = "0123456789abcdef"
    resultat_hex = ""
    
    while entier > 0:
        reste = entier % 16
        resultat_hex = caracteres_hex[reste] + resultat_hex
        entier //= 16
    
    return "0x" + resultat_hex if resultat_hex else "0x0"

def extraire(chaine):
    chaine_str = str(chaine)
    caracteres_indesirables = [' ', '.', 'e', 'P','u','b','l','i','c',':','f','o','r','=','n','h','[',']','\n']
    table_de_translation = str.maketrans('', '', ''.join(caracteres_indesirables))
    nouvelle_chaine = chaine_str.translate(table_de_translation)
    nouvelle_chaine = nouvelle_chaine[3:]
    nombres = nouvelle_chaine.split(',')
    nombres_hex = [hex(int(nombre))[2:] for nombre in nombres]
    resultat = ','.join(nombres_hex)
    caracteres_indesirables2 = [',']
    table_de_translation = str.maketrans('', '', ''.join(caracteres_indesirables2))
    nouvelle_chaine2 = resultat.translate(table_de_translation)
    return nouvelle_chaine2

def measure_size():
    i = 0
    total = 0
    for i in range(50):
        json = create_json_transaction()
        total += measure_json_file(json)
        print(measure_json_file(json))
        i+=1
    total = total/50
    return total


create_json_transaction()


