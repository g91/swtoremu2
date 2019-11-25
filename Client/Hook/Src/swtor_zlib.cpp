#include "StdAfx.h"
#include "swtor_zlib.h"

swzlib::swzlib()
{
	mInboundStream.zalloc = Z_NULL;
	mInboundStream.zfree = Z_NULL;
	mInboundStream.opaque = Z_NULL;
	inflateInit2_(&mInboundStream, -8, "1.2.3", sizeof(mInboundStream));

	mOutboundStream.zalloc = Z_NULL;
	mOutboundStream.zfree = Z_NULL;
	mOutboundStream.opaque = Z_NULL;
	deflateInit2_(&mOutboundStream, -1, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY, "1.2.3", sizeof(mOutboundStream));
}

int swzlib::swtor_decompress(Bytef *source, Bytef *dest, int sizeIn, int sizeOut)
{

	mInboundStream.avail_in = sizeIn - 6;
	mInboundStream.next_in = source + 6;
	mInboundStream.avail_out = sizeOut;
	mInboundStream.next_out = dest;

	int flush = Z_NO_FLUSH;         // Z_FINISH;   
	int ret = inflate(&mInboundStream, flush);
	return ret;
	/*int ret;
	unsigned have;
	int total = 0;

	Bytef* inbound = new Bytef[sizeIn - 2];
	memcpy(inbound, source+6, sizeIn-6);
	inbound[sizeIn - 3] = 0xFF;
	inbound[sizeIn - 4] = 0xFF;
	inbound[sizeIn - 5] = 0x00;
	inbound[sizeIn - 6] = 0x00;

	mInboundStream.avail_in = sizeIn-2;
	if (mInboundStream.avail_in == 0)
		return 0;
	mInboundStream.next_in = inbound;

	do {
		mInboundStream.avail_out = sizeOut;
		mInboundStream.next_out = dest;
		ret = inflate(&mInboundStream, Z_FULL_FLUSH);
		have = sizeOut - mInboundStream.avail_out;
		total += have;

		if(ret != 0)
			printf(mInboundStream.msg);

		printf("ret = %d\n", ret);
		switch (ret) {
		case Z_NEED_DICT:
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			delete[] inbound;
			return 0;
		}
	} while (mInboundStream.avail_out == 0);

	delete[] inbound;

	return total;*/
}

int swzlib::swtor_compress(Byte* inbuf, int insize, Byte* outbuf, int outsize)
{
	z_stream zs;
	int result;

	zs.zalloc = Z_NULL;
	zs.zfree = Z_NULL;
	zs.opaque = Z_NULL;
	result = deflateInit2_(&zs, -1, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY, "1.2.3", sizeof(zs));

	zs.avail_in = insize + 6;
	zs.next_in = inbuf - 6;
	zs.avail_out = outsize;
	zs.next_out = outbuf;

	deflate(&zs, 2);
	deflateEnd(&zs);
	return outsize - mOutboundStream.avail_out;
	
}