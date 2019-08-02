import asyncio
import logging

import aiocoap
from aiocoap.numbers.codes import Code
from kibra.tlv import ThreadTLV


class CoapClient():
    '''Perform CoAP petitions to the Thread Diagnostics port'''

    def __init__(self):
        self.context = None

    async def con_request(self, addr, port, path, payload=''):
        return await self.request(addr, port, path, aiocoap.CON, payload)

    async def non_request(self, addr, port, path, payload=''):
        await self.request(addr, port, path, aiocoap.NON, payload)

    async def request(self, addr, port, path, mtype, payload=''):
        '''Client request'''
        if self.context is None:
            self.context = await aiocoap.Context.create_client_context()
        req = aiocoap.Message(code=Code.POST, mtype=mtype, payload=payload)
        uri = 'coap://[%s]:%u%s' % (addr, port, path)
        req.set_request_uri(uri=uri, set_uri_host=False)
        logging.debug('tx: %s %s' % (uri, ThreadTLV.sub_tlvs_str(payload)))
        try:
            # Workaround for not waiting a response to a non-confirmable request
            if mtype == aiocoap.NON:
                try:
                    await asyncio.wait_for(
                        self.context.request(req).response, timeout=0.001)
                except asyncio.TimeoutError:
                    return
            else:
                response = await self.context.request(req).response
        except:
            logging.warn('No response from %s', addr)
        else:
            logging.debug(
                'rx: %s %s %s' % (addr, response.code,
                                  ThreadTLV.sub_tlvs_str(response.payload)))
            return response.payload

    def stop(self):
        if self.context is not None:
            self.context.shutdown()
