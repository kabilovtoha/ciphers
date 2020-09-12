
from cryptography.fernet import Fernet
import os

f_name = 'komplex9.mp4'
# f_name = 'inf.txt'
end = f_name[(f_name.rfind(".") + 1):]
fp = os.path.join(os.getcwd(), 'test_vals', 'big', f_name)
fp_key = os.path.join(os.getcwd(), 'test_vals', 'big', 'tmp', f'{f_name}__KEY')
sh_recept = os.path.join(os.getcwd(), 'test_vals', 'big', 'tmp', f'{f_name}__RECEPT')
nfp = os.path.join(os.getcwd(), 'test_vals', 'big','tmp', f'{f_name}__encr__.{end}')
de_nfp = os.path.join(os.getcwd(), 'test_vals', 'big','tmp', f'{f_name}__DE__.{end}')

max_part_bytes = 300 * 1000 * 1000
import time
import shelve

def count_2(of):
    return len(of.readlines())
def count_1(of):
    c = 0
    row_length = 0
    for l in of:
        c += 1
        row_length += len(l)
    print('row_length', row_length / c)
    return c

def __time(fun):
    of = open(fp, 'rb')
    t1 = time.time()
    fun(of)
    t2 = time.time()
    print('fun t', t2 - t1)
    of.close()

# __time(count_1)
# __time(count_2)

class Crypto():
    """
    при шифровании если enсrypt_all != True
        то шифруем часть блоков согласно enсrypt_iter
    enсrypt_iter  ключ количество блоков, значение означает что каждый блок идущий после
     предыдущего на указанное значение будет зашифрован
    """
    max_part_bytes = 300 * 1000 * 1000
    encrypt_iter = {1: 1, 2: 3, 3: 4, 4: 3, 5: 4}
    max_enc_iter = 3

    def __init__(self, encrypt_all=False, max_part_bytes=None, size=None):
        """

        :param enсrypt_all: boolean
        :param max_part_bytes: int  mb
        """
        self.encrypt_all = encrypt_all
        if max_part_bytes:
            self.max_part_bytes = max_part_bytes * 1000 * 1000
        self.size = size


    def file_encrypt(self, file_path, new_path, size=None):
        if not size:
            size = self.count_size(file_path)
        fr = open(file_path, 'rb')
        fw = open(new_path, 'wb')
        F = self.set_key()

        c_blocks = size // self.max_part_bytes
        if size % self.max_part_bytes:
            c_blocks += 1
        if c_blocks in self.encrypt_iter.keys():
            enc_iter = self.encrypt_iter.get(c_blocks)
        else:
            enc_iter = self.max_enc_iter

        bl_num = 1
        bl = fr.read(max_part_bytes)
        enc_recept = []
        while bl:
            if bl_num == 1 or (bl_num % enc_iter) == 0:
                encrypt_data = F.encrypt(bl)
                fw.write(encrypt_data)
                enc_recept.append([len(encrypt_data), True])
            else:
                if bl_num == c_blocks:
                    size = len(bl)
                else:
                    size = self.max_part_bytes
                fw.write(bl)
                enc_recept.append([size, False])
            bl = fr.read(max_part_bytes)
            bl_num += 1
        fr.close()
        fw.close()
        with shelve.open(sh_recept) as sh_f:
            sh_f['enc_recept'] = enc_recept
        sh_f = shelve.open(sh_recept)

    def file_decrypt(self):
        fr = open(nfp, 'rb')
        fw = open(de_nfp, 'wb')
        sh_f = shelve.open(sh_recept)
        enc_recept = sh_f.get('enc_recept')

        fk = open(fp_key, 'rb')
        key = fk.read()
        F = Fernet(key)
        if enc_recept:
            for size, is_encrypt in enc_recept:
                if is_encrypt:
                    data = F.decrypt(fr.read(size))
                    fw.write(data)
                else:
                    fw.write(fr.read(size))
        fr.close()
        fw.close()
        fk.close()

    def set_key(self):
        key = Fernet.generate_key()
        F = Fernet(key)
        with open(fp_key, 'wb') as fk:
            fk.write(key)
        return F

    def count_size(self, file_path):
        fr = open(file_path, 'rb')
        l = len(fr.read(self.max_part_bytes))
        length = l
        while l:
            l = len(fr.read(self.max_part_bytes))
            length += l
        fr.close()
        return length

crypto = Crypto()

crypto.file_encrypt(fp, nfp)
crypto.file_decrypt()

def decrypt():
    onf = open(nfp, 'rb')
    nf = open(de_nfp, 'wb')
    fk = open(fp_key, 'rb')
    key = fk.read()
    f = Fernet(key)
    for c,l in enumerate(onf):
        c += 1
        if c == 1:
            print(f'len(l): {len(l)}')
            to_decrypt = l[:l.rfind(b'\n')]
            print(f'len(to_decrypt): {len(to_decrypt)}')
            decrypted_data = f.decrypt(to_decrypt)
            # decrypted_data = f.decrypt(l)
            nf.write(decrypted_data)
            nf.write(b'\n')
        else:
            nf.write(l)
    nf.close()
    onf.close()


    nf = open(de_nfp, 'rb')
    print(count_1(nf))
    nf.close()


def ecnrypt():
    key = Fernet.generate_key()
    f = Fernet(key)
    with open(fp_key, 'wb') as fk:
        fk.write(key)

    of = open(fp, 'rb')
    count = count_1(of)
    print(count)
    of.close()

    of = open(fp, 'rb')
    nf = open(nfp,'wb')

    h = count // 2
    print('h - ', h)
    part_enc = b''
    for c,l in enumerate(of):
        c += 1
        if c < h:
            part_enc += l
        elif c == h:
            part_enc += l
            print(r"part_enc", part_enc)
            if part_enc.endswith(b'\n'):
                print(r"part_enc.endswith('\n')")
                print(f'part_enc 1 {len(part_enc)}: ')
                part_enc = part_enc[:(part_enc.rfind(b'\n'))]
                print(f'part_enc 2 {len(part_enc)}: ')
            enc_data = f.encrypt(part_enc)
            print('type(enc_data)', type(enc_data))
            # encrypted_data = enc_data + b'\n'
            nf.write(enc_data)
            nf.write(b'\n')
        elif c > h:
            nf.write(l)
    nf.close()

    onf = open(nfp, 'rb')
    print(count_1(onf))
    onf.close()

# ecnrypt()
# decrypt()