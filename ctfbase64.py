#encoding:utf-8
import re

ZERO_CHAR = "="
NONE_CHAR = "*"

Default_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

class Form:
    def __init__(self):
        self.form = {}
    def __str__(self):
        return self.form.__str__()

    def get(self,key):
        if key in self.form.keys():
            return self.form[key]
        else:
            return None
    
    def add(self,key,value):
        list_keys = list(self.form.keys())
        list_values = list(self.form.values())
        if value in list_values:
            if key in list_keys and self.form[key] == value:
                return
            else:
                old_key = list_keys[list_values.index(value)]
                raise Exception("Form.form['{}'] has the value:'{}' but not add new key:'{}' for same value".format(old_key,value,key))
        if key in list_keys:
            if self.form[key] != value:
                raise Exception("Form.form['{}'] has the value:'{}' but now to set '{}'".format(key,self.form[key],value))
        else:
            self.form[key] = value

class EncodeForm(Form):
    def init(self,table_str,*,none_char="*"):
        if len(table_str) != 64:
            raise Exception("table_str's length must be 64")
        for i in range(0,64):
            if table_str[i] != none_char:
                key = format(i,'0>6b')
                self.add(key,table_str[i])

    def get(self,key):
        if type(key) == str:
            if re.match(r'^[0,1]{6}$',key):
                return super().get(key)
        if type(key) == int:
            if key >=0 and key < 64:
                key = format(key,'0>6b')
                return super().get(key)
        raise Exception("Error type key {},only str or int".format(type(key)))

    def add(self,key,value):
        if type(key) == str:
            if re.match(r'^[0,1]{6}$',key):
                super().add(key,value)
                return 
        if type(key) == int:
            if key >=0 and key < 64:
                key = format(key,'0>6b')
                super().add(key,value)
                return
        raise Exception("Encode Form error key:{}".format(key))
    
    def to_table_string(self):
        table_str = bytearray((NONE_CHAR*64).encode())
        for key in self.form.keys():
            i = int(key,2)
            table_str[i] = ord(self.get(key))
        return table_str.decode()
    
    def keys(self):
        return [int(key,2) for key in self.form.keys()]

class DecodeForm(Form):
    def init(self,table_str,*,none_char="*"):
        if len(table_str) != 64:
            raise Exception("table_str's length must be 64")
        for i in range(0,64):
            if table_str[i] != none_char:
                value = format(i,'0>6b')
                self.add(table_str[i],value)
    
    def init_from_encodeform(self,encode_form):
        assert isinstance(encode_form,EncodeForm)
        for key in encode_form.form.keys():
            self.add(encode_form.form[key],key)

    def add(self,key,value):
        if type(value) == str:
            if re.match(r'^[0,1]{6}$',value):
                super().add(key,value)
                return
        if type(value) == int:
            if value >=0 and value < 64:
                value = format(value,'0>6b')
                super().add(key,value)
                return
        raise Exception("Encode Form error value:{}".format(key))
    def to_table_string(self):
        table_str = bytearray((NONE_CHAR*64).encode())
        for key in self.form.keys():
            i = int(self.get(key),2)
            table_str[i] = ord(key)
        return table_str.decode()
        

def _get_encode_form(en_str,de_str,encode_form):
    assert len(en_str) == 4
    assert isinstance(encode_form,EncodeForm)
    if ZERO_CHAR in en_str:
        idx = en_str.index(ZERO_CHAR)
        if idx == 2:
            assert len(de_str) == 1
            de_byte = bytearray(de_str.encode())
            de_binary = ''.join(format(x,'0>8b') for x in de_byte)
            de_binary = de_binary+"0000"
        elif idx == 3:
            assert len(de_str) == 2
            de_byte = bytearray(de_str.encode())
            de_binary = ''.join(format(x,'0>8b') for x in de_byte)
            de_binary = de_binary+"00"            
        else:
            raise Exception("'{}''s situation is wrong for {}".format(ZERO_CHAR,en_str))
    else:
        de_byte = bytearray(de_str.encode())
        de_binary = ''.join(format(x,'0>8b') for x in de_byte)
    keys = [de_binary[i:i+6] for i in range(0,len(de_binary),6)]
    for i in range(0,len(keys)):
        encode_form.add(keys[i],en_str[i])

def get_encode_form(en_str,de_str):
    en_form = EncodeForm()
    en_length = len(en_str)
    de_length = len(de_str)
    assert en_length % 4 == 0
    if ZERO_CHAR in en_str:
        assert en_str.index(ZERO_CHAR) > en_length-3
    if (de_length % 3): 
        assert (en_length//4) == (de_length//3)+1
    else:
        assert (en_length//4) == (de_length//3)
    for i in range(0,en_length//4):
        _get_encode_form(en_str[i*4:(i+1)*4],de_str[i*3:(i+1)*3],en_form)
    return en_form


def b64_encode(de_str,*,table = Default_table):
    encode_form = EncodeForm()
    encode_form.init(table)
    add_zero_char_num = (3 - (len(de_str) % 3)) % 3
    de_str_bin = ""
    for s in de_str:
        de_str_bin += format(ord(s),'0>8b')
    de_str_bin += add_zero_char_num*"00"
    en_str = ""
    for i in range(0,len(de_str_bin),6):
        key = de_str_bin[i:i+6]
        value = encode_form.get(key)
        if value is None:
            raise Exception("Can't find encode char in encode_table,index is {:d}".format(int(key,2)))
        else:
            en_str += value
    en_str += ZERO_CHAR*add_zero_char_num
    return en_str

def b64_decode(en_str,*,table = Default_table,pad_list=[]):
    en_str_length = len(en_str)
    assert (en_str_length % 4) == 0
    decode_form = DecodeForm()
    decode_form.init(table)
    decode_result = []
    all_find = True
    for i in range(0,en_str_length,4):
        en_str_4char = en_str[i:i+4]
        idx = 4
        has_pad = False
        not_find_chr = []
        not_find = False
        if ZERO_CHAR in en_str_4char:
            idx = en_str_4char.index(ZERO_CHAR)
            if idx < 2:
                raise Exception("Error base64 encode string {}".format(en_str_4char))
            if idx == 2:
                pad_idx = (8,12)
                has_pad = True
            if idx == 3:
                pad_idx = (16,18)
                has_pad = True
        de_str_binary = ""
        for j in range(0,idx):
            tmp_chr = decode_form.get(en_str_4char[j])
            if tmp_chr:
                de_str_binary += tmp_chr
            else:
                not_find_chr.append(en_str_4char[j])
                not_find = True
        if not_find:
            decode_result.append({'en':en_str_4char,'de':"Can't find key {}".format(",".join(not_find_chr))})
            all_find = False
            continue
        if has_pad:
            pad_list.append(de_str_binary[pad_idx[0]:pad_idx[1]])
            de_str_binary = de_str_binary[0:pad_idx[0]]
        de_str = b''
        for j in range(0,len(de_str_binary),8):
            de_str += bytes([int(de_str_binary[j:j+8],2)])
        decode_result.append({"en":en_str_4char,"de":de_str})
    decode_string = b''
    for data in decode_result:
        if all_find:
            decode_string += data['de']
        else:
            print("{}:{}".format(data['en'],data['de']))
    return decode_string
