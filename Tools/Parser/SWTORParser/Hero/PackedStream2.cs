using System.IO;

namespace SWTORParser.Hero
{
    public class PackedStream2 : PackedStream
    {
        public uint M10;
        public SerializeStateBase State;

        public PackedStream2(int style, byte[] data)
            : base(style, new MemoryStream(data))
        {
            State = null;
            M10 = 0U;
            TransportVersion = 5;
        }

        public PackedStream2(int style, Stream stream)
            : base(style, stream)
        {
            State = null;
            M10 = 0U;
            TransportVersion = 5;
        }

        public PackedStream2(int style)
            : base(style, new MemoryStream())
        {
            State = null;
            M10 = 0U;
            TransportVersion = 5;
        }
    }
}