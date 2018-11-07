import logging

import aiocoap
from aiocoap.numbers.codes import Code


class CoapClient():
    '''Perform CoAP petitions to the Thread Diagnostics port'''

    def __init__(self):
        self.protocol = None

    async def request(self, addr, port, path, payload=''):
        '''Client request'''
        if self.protocol is None:
            self.protocol = await aiocoap.Context.create_client_context()
        req = aiocoap.Message(
            code=Code.POST, mtype=aiocoap.CON, payload=payload)
        req.set_request_uri(
            uri='coap://[%s]:%u%s' % (addr, port, path), set_uri_host=False)
        try:
            response = await self.protocol.request(req).response
        except Exception:
            logging.debug('No response from %s', addr)
            return None
        else:
            logging.debug('%s responded with %s.', addr, response.code)
            return response.payload

    def stop(self):
        self.protocol.shutdown()
