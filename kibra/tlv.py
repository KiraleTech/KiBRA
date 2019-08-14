class ThreadTLV:
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
        # TODO: extended length
        self.length = int(self.data[1])
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
        if not data:
            return tlvs
        elif isinstance(data, str):
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

    @staticmethod
    def sub_tlvs_str(payload):
        sub_tlvs = ThreadTLV.sub_tlvs(payload)
        result = ''
        for tlv in sub_tlvs:
            result += '{ %s } ' % tlv
        return result

    @staticmethod
    def get_value(data, type_):
        '''Return the array value of the TLV of type type_ from data'''
        for tlv in ThreadTLV.sub_tlvs(data):
            if tlv.type == type_:
                # TODO: check size depending on the type
                return tlv.value
        return None
