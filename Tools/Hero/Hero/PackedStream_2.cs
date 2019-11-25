using System.IO;

namespace Hero
{
  public class PackedStream_2 : PackedStream
  {
    public SerializeStateBase State;
    public uint m_10;

    public PackedStream_2(int style, byte[] data)
      : base(style, (Stream) new MemoryStream(data))
    {
      this.State = (SerializeStateBase) null;
      this.m_10 = 0U;
      this.TransportVersion = (ushort) 5;
    }

    public PackedStream_2(int style, Stream stream)
      : base(style, stream)
    {
      this.State = (SerializeStateBase) null;
      this.m_10 = 0U;
      this.TransportVersion = (ushort) 5;
    }

    public PackedStream_2(int style)
      : base(style, (Stream) new MemoryStream())
    {
      this.State = (SerializeStateBase) null;
      this.m_10 = 0U;
      this.TransportVersion = (ushort) 5;
    }
  }
}
