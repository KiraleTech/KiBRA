class ThreadTLV():
    '''Thread TLV representation'''

    def __init__(self, data=None, t=None, l=None, v=None):
        if isinstance(data, str):
            self.data = bytearray.fromhex(data)
        elif isinstance(data, bytes):
            self.data = bytearray(data)
        elif isinstance(data, bytearray):
            self.data = data
        elif data is None and isinstance(t, int) and isinstance(l, int):
            self.data = bytearray()
            self.data.append(t)
            self.data.append(l)
            if l > 0:
                self.data.extend(bytearray(v))
        else:
            raise Exception('Bad data.')

        self.type = int(self.data[0])
        self.length = int(self.data[1])
        if self.length > 0:
            self.value = self.data[2:]

    def __str__(self):
        result = '%3u | %3u |' % (self.type, self.length)
        if self.length != 0:
            for byte in self.value:
                result += ' %02x' % byte
        return result

    def array(self):
        '''TLV data as bytearray'''
        return self.data

    @staticmethod
    def sub_tlvs(data=None):
        '''Generate ThreadTLV objects with the contents of the current TLV'''
        tlvs = []
        if isinstance(data, str):
            data = bytearray.fromhex(data)
        elif isinstance(data, bytes):
            data = bytearray(data)
        elif isinstance(data, bytearray):
            pass
        else:
            raise Exception('Bad data.')

        while len(data) > 1:
            size = int(data[1]) + 2
            tlvs.append(ThreadTLV(data[:size]))
            data = data[size:]
        return tlvs
