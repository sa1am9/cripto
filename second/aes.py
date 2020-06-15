import os
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest


class AES128:

    def __init__(self, key):
        self.nRounds = AES128.GetNRounds(key)
        self.rCon = AES128.RCon()
        self.sBox = AES128.GetSBox()
        self.invSBox = AES128.GetInvSBox()
        self.kMatrix = self.ExpKey(key)

    @staticmethod
    def BXor(x, y):
        return bytes(i ^ j for i, j in zip(x, y))

    @staticmethod
    def GetMatrix(data):
        return [list(data[i * 4:(i + 1) * 4]) for i in range(0, 4)]

    @staticmethod
    def GetBytes(data):
        return bytes(sum(data, []))

    @staticmethod
    def GetNRounds(key):
        return {16: 10, 24: 12, 32: 14}[len(key)]

    @staticmethod
    def SplitData(data, step=16):
        rez = []
        for i in range(0, len(data), step):
            rez += [data[i:i + step]]
        return rez

    @staticmethod
    def GetSBox():
        eSBox = None
        with open("sBox", 'r') as sBox:
            eSBox = sBox.read()
        return eval(eSBox)

    @staticmethod
    def GetRCon():
        eRCon = None
        with open("rCon", 'r') as rCon:
            eRCon = rCon.read()
        return eval(eRCon)

    @staticmethod
    def GetInvSBox():
        eInvSBox = None
        with open("invSBox", 'r') as invSBox:
            eInvSBox = invSBox.read()
        return eval(eInvSBox)

    @staticmethod
    def MixColumns(data):
        def supF(x):
            if x & 0x80:
                return 0xFF & ((x << 1) ^ 0x1B)
            else:
                return x << 1

        rez = data

        for i in range(4):
            t = rez[i][0] ^ rez[i][1] ^ rez[i][2] ^ rez[i][3]
            tmp = rez[i][0]
            rez[i][0] ^= t ^ supF(rez[i][0] ^ rez[i][1])
            rez[i][1] ^= t ^ supF(rez[i][1] ^ rez[i][2])
            rez[i][2] ^= t ^ supF(rez[i][2] ^ rez[i][3])
            rez[i][3] ^= t ^ supF(rez[i][3] ^ tmp)

        return rez

    @staticmethod
    def InvMixColumns(data):
        def supF(x):
            if x & 0x80:
                return 0xFF & ((x << 1) ^ 0x1B)
            else:
                return x << 1

        rez = data
        for i in range(4):
            t1 = supF(supF(rez[i][0] ^ rez[i][2]))
            t2 = supF(supF(rez[i][1] ^ rez[i][3]))
            rez[i][0] ^= t1
            rez[i][1] ^= t2
            rez[i][2] ^= t1
            rez[i][3] ^= t2
        rez = AES128.MixColumns(rez)
        return rez

    @staticmethod
    def ShiftRows(data):
        shift = lambda d, i, j: (d[i % 4][j], d[(i + 1) % 4][j], d[(i + 2) % 4][j], d[(i + 3) % 4][j])
        rez = data
        for i in range(1, 4):
            rez[0][i], rez[1][i], rez[2][i], rez[3][i] = shift(rez, i, i)
        return rez

    @staticmethod
    def InvShiftRows(data):
        shift = lambda d, i, j: (d[i % 4][j], d[(i + 1) % 4][j], d[(i + 2) % 4][j], d[(i + 3) % 4][j])
        rez = data
        for i in range(1, 4):
            rez[0][i], rez[1][i], rez[2][i], rez[3][i] = shift(rez, 4 - i, i)
        return rez

    def ExpKey(self, key):

        kCols = AES128.GetMatrix(key)
        t = len(key) // 4
        i = 1

        while len(kCols) / 4 < self.nRounds + 1:
            data = list(kCols[-1])
            if len(kCols) % t == 0:
                data += [data.pop(0)]
                data = [self.sBox[b] for b in data]
                data[0] ^= self.rCon[i]
                i += 1
            elif len(key) == 32 and len(kCols) % t == 4:
                data = [self.sBox[b] for b in data]

            data = AES128.BXor(data, kCols[-t])
            kCols += [data]
        return [kCols[4 * i: 4 * (i + 1)] for i in range(len(kCols) // 4)]

    def PureEncrypt(self, data):

        data = AES128.GetMatrix(data)

        for i in range(4):
            for j in range(4):
                data[i][j] ^= self.kMatrix[0][i][j]

        for k in range(1, self.nRounds):
            for i in range(4):
                for j in range(4):
                    data[i][j] = self.sBox[data[i][j]]
            data = AES128.ShiftRows(data)
            data = AES128.MixColumns(data)

            for i in range(4):
                for j in range(4):
                    data[i][j] ^= self.kMatrix[k][i][j]

        for i in range(4):
            for j in range(4):
                data[i][j] = self.sBox[data[i][j]]
        data = AES128.ShiftRows(data)

        for i in range(4):
            for j in range(4):
                data[i][j] ^= self.kMatrix[-1][i][j]
        data = AES128.GetBytes(data)

        return data

    def PureDecrypt(self, data):

        data = AES128.GetMatrix(data)

        for i in range(4):
            for j in range(4):
                data[i][j] ^= self.kMatrix[-1][i][j]
        data = AES128.InvShiftRows(data)
        for i in range(4):
            for j in range(4):
                data[i][j] = self.invSBox[data[i][j]]
        for k in range(1, self.nRounds):
            for i in range(4):
                for j in range(4):
                    data[i][j] ^= self.kMatrix[self.nRounds - k][i][j]
            data = AES128.InvMixColumns(data)
            data = AES128.InvShiftRows(data)
            for i in range(4):
                for j in range(4):
                    data[i][j] = self.invSBox[data[i][j]]

        for i in range(4):
            for j in range(4):
                data[i][j] ^= self.kMatrix[0][i][j]

        data = AES128.GetBytes(data)

        return data

    def CBCEnc(self, data, iv):

        data += bytes([16 - (len(data) % 16)] * (16 - (len(data) % 16)))

        rez = []
        t = iv
        for _data in AES128.SplitData(data):
            rez += [self.PureEncrypt(AES128.BXor(_data, t))]
            t = rez[-1]
        rez = b''.join(rez)
        return rez

    def CBCDec(self, data, iv):
        rez = []
        t = iv
        for _data in self.SplitData(data):
            rez += [AES128.BXor(t, self.PureDecrypt(_data))]
            t = _data

        rez = b''.join(rez)
        print(rez)
        t = rez[-1]
        rez = rez[:-t]

        return rez


def encrypt(key, data, n=100000):
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')

    salt = os.urandom(16)

    t = pbkdf2_hmac('sha256', key, salt, n, 16 * 3)
    key = t[:16]
    hmacKey = t[:16]
    iv = t[:16]

    data = AES128(key).CBCEnc(data, iv)

    return new_hmac(hmacKey, salt + data, 'sha256').digest() + salt + data


def decrypt(key, data, n=100000):
    if isinstance(key, str):
        key = key.encode('utf-8')

    hmac = data[:32]
    data = data[32:]
    salt = data[:16]
    data = data[16:]

    t = pbkdf2_hmac('sha256', key, salt, n, 16 * 3)
    print(t)
    key = t[:16]
    hmacKey = t[:16]
    iv = t[:16]
    data = AES128(key).CBCDec(data, iv)
    return data.encode('utf-8')