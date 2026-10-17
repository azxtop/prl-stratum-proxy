"""Async server-side TLS via SSL MemoryBIO; no trust-store or miner changes."""
import asyncio
import ssl

class TLSStream:
    def __init__(self,reader,writer,context):
        self.reader=reader;self.writer=writer
        self.incoming=ssl.MemoryBIO();self.outgoing=ssl.MemoryBIO()
        self.ssl=context.wrap_bio(self.incoming,self.outgoing,server_side=True)
        self.buffer=b'';self.pending=bytearray();self.eof=False

    async def flush(self):
        while self.outgoing.pending:
            self.writer.write(self.outgoing.read())
        await self.writer.drain()

    async def feed(self):
        data=await self.reader.read(65536)
        if not data:
            self.eof=True;self.incoming.write_eof()
        else:self.incoming.write(data)

    async def handshake(self):
        while True:
            try:
                self.ssl.do_handshake();await self.flush();return
            except ssl.SSLWantReadError:
                await self.flush()
                await self.feed()
                if self.eof:raise ConnectionError('TLS client closed during handshake')
            except ssl.SSLWantWriteError:await self.flush()

    async def read(self,n=65536):
        while True:
            try:
                data=self.ssl.read(n)
                await self.flush()
                return data
            except ssl.SSLWantReadError:
                await self.flush()
                if self.eof:return b''
                await self.feed()
            except (ssl.SSLZeroReturnError,ssl.SSLEOFError):return b''

    async def readline(self):
        while b'\n' not in self.buffer:
            chunk=await self.read()
            if not chunk:
                line,self.buffer=self.buffer,b'';return line
            self.buffer+=chunk
            if len(self.buffer)>32*1024*1024:raise ValueError('TLS PRL line exceeds buffer')
        line,self.buffer=self.buffer.split(b'\n',1)
        return line+b'\n'

    def write(self,data):self.pending.extend(data)

    async def drain(self):
        while self.pending:
            try:
                n=self.ssl.write(bytes(self.pending[:65536]));del self.pending[:n]
                await self.flush()
            except ssl.SSLWantWriteError:await self.flush()
        await self.flush()

    def close(self):self.writer.close()

    async def wait_closed(self):
        try:await self.writer.wait_closed()
        except (ssl.SSLError,OSError):pass
