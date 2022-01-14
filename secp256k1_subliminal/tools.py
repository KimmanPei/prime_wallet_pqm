from ctypes import *
from ctypes.util import *
import os

libpath = os.path.dirname(__file__)
libpath = os.path.join(libpath, 'dep', 'libsecp256k1_subliminal.dll')
#os.add_dll_directory(r'D:\mingw64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin') # 这里要修改
corelib = CDLL(libpath)


class Pubkey:
    def __init__(self, data):
        if isinstance(data, str):
            data = bytes.fromhex(data)

        if isinstance(data, bytes):
            if len(data) == 65 or len(data) == 33:
                _data = create_string_buffer(64)
                if corelib.C_pubKeyParse(_data, data, len(data)):
                    self._data = _data.raw
                    return
                else:
                    raise ValueError('cannot parse pubkey')

            elif len(data) == 64:
                self._data = data
            else:
                raise ValueError('Invalid argument for pubkey!')
        else:
            raise TypeError()

    def serialize(self, compress=True):
        raw = create_string_buffer(65);
        if compress:
            corelib.C_pubkeySerialize(raw, self._data, 1);
            return raw.raw[0:33]
        else:
            corelib.C_pubkeySerialize(raw, self._data, 0);
            return raw.raw

    def getKey(self):
        return self._data

    @classmethod
    def fromSeckey(cls, seckey):
        pk_raw = create_string_buffer(64)
        if corelib.C_pkFromSk(pk_raw, seckey.getKey()):
            return cls(pk_raw.raw)
        else:
            raise RuntimeError('Invalid Seckey')

    def verify(self, data, sig):
        if corelib.C_hashVerify(data, len(data), sig, len(sig), self._data):
            return True
        else:
            return False

    def __repr__(self):
        return self._data.hex()

    def __eq__(self, other):
        return repr(self) == repr(other)

class Seckey:
    def __init__(self, data = None):
        if isinstance(data, bytes):
            assert len(data) == 32
            self._data = data

        elif isinstance(data, str):
            assert len(data) == 64
            self._data = bytes.fromhex(data)

    def __repr__(self):
        return self._data.hex()

    def getKey(self):
        return self._data

    def sign(self, data, msg=None):
        sig_raw = create_string_buffer(200)
        sig_sz = c_int()
        if msg is None:
            corelib.C_hashSign(sig_raw, byref(sig_sz), data, len(data), self.getKey())

        else:
            if len(msg) != 31:
                raise ValueError('cannot hide msg in this signature')
            corelib.C_hashSignWithMsg(sig_raw, byref(sig_sz), data, len(data), self.getKey(), msg)
        return sig_raw.raw[0:sig_sz.value]

    def verify(self, data, sig):
        msg_raw = create_string_buffer(31)
        if corelib.C_hashVerifyWithMsg(msg_raw, data, len(data), sig, len(sig), self.getKey()):
            return (True, msg_raw.raw)
        else:
            return (False, None)

    def __eq__(self, other):
        return repr(self) == other.getKey()


def keyGen():
    pk_raw = create_string_buffer(64)
    sk_raw = create_string_buffer(32)
    if corelib.C_genKeypair(pk_raw, sk_raw):
        return (Pubkey(pk_raw.raw), Seckey(sk_raw.raw))
    else:
        raise RuntimeError('Failed to generate keypair')

# print('done')
