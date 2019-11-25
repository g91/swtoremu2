class swzlib {
	z_stream mInboundStream;
	z_stream mOutboundStream;

public:
	swzlib();
	int swtor_decompress(Bytef *source, Bytef *dest, int sizeIn, int sizeOut);
	int swtor_compress(Byte* inbuf, int insize, Byte* outbuf, int outsize);
};