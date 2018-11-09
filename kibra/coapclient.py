import logging
import asyncio

import aiocoap
from aiocoap.numbers.codes import Code


class CoapClient():
    '''Perform CoAP petitions to the Thread Diagnostics port'''

    def __init__(self):
        self.protocol = None

    async def con_request(self, addr, port, path, payload=''):
        return await self.request(addr, port, path, aiocoap.CON, payload)

    async def non_request(self, addr, port, path, payload=''):
        await self.request(addr, port, path, aiocoap.NON, payload)

    async def request(self, addr, port, path, mtype, payload=''):
        '''Client request'''
        if self.protocol is None:
            self.protocol = await aiocoap.Context.create_client_context()
        req = aiocoap.Message(code=Code.POST, mtype=mtype, payload=payload)
        uri = 'coap://[%s]:%u%s' % (addr, port, path)
        req.set_request_uri(uri=uri, set_uri_host=False)
        try:
            # Workaround for not waiting a response to a non-confirmable request
            if mtype == aiocoap.NON:
                try:
                    await asyncio.wait_for(
                        self.protocol.request(req).response, timeout=0.01)
                except asyncio.TimeoutError:
                    return
            else:
                response = await self.protocol.request(req).response
        except:
            logging.debug('No response from %s', addr)
        else:
            logging.debug('%s responded with %s.', addr, response.code)
            return response.payload

    def stop(self):
        self.protocol.shutdown()
