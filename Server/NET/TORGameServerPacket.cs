using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using ComponentAce.Compression.Libs.zlib;

namespace NexusToRServer.NET
{
    public abstract class TORGameServerPacket : SPacket
    {
        protected Boolean _invisible = false;
        private Boolean _enc = true;
        private Boolean _def = true;

        public abstract void WriteImplementation();
        public void RunImplementation() { }

        /// <summary>
        /// Prevent packets from 'invisible' players from being broadcasted
        /// </summary>
        public Boolean Invisible
        {
            get { return _invisible; }
            set { _invisible = value; }
        }

        public Boolean Encrypted
        {
            get { return _enc; }
            set { _enc = value; }
        }

        public Boolean Deflated
        {
            get { return _def; }
            set { _def = value; }
        }

        public override void Write()
        {
            try
            {
                WriteImplementation();
            }
            catch
            {
                Log.Write(LogLevel.Error, "Failed writing '{0}'", GetType().ToString());
            }
        }

        public byte[] Construct(IStreamCipher encryptor, ZStream dStream)
        {
            Log.Write(LogLevel.Client, "Constructing Packet [{0}]", GetType().ToString());

            byte[] cData = _stream.ToArray();

            //Log.Write(LogLevel.Error, "{0}", cData.ToHEX());

            if (_def)
            {
                MemoryStream lStream = new MemoryStream();

                dStream.avail_in = cData.Length;
                dStream.next_in = cData;
                dStream.next_in_index = 0;

                byte[] dData = new byte[cData.Length * 2];

                dStream.avail_out = cData.Length * 2;
                dStream.next_out = dData;
                dStream.next_out_index = 0;

                dStream.deflate(2);

                lStream.Write(dData, 0, (cData.Length * 2) - dStream.avail_out);
                cData = lStream.ToArray();
                lStream.Dispose();
            }

            MemoryStream oStream = new MemoryStream();
            EndianBinaryWriter oWriter = new EndianBinaryWriter(MiscUtil.Conversion.EndianBitConverter.Little, oStream);

            oWriter.Write((byte)GetModule());
            oWriter.Write((UInt32)cData.Length + 2);
            oWriter.Write((byte)GenerateChecksum(oStream.ToArray()));
            oWriter.Write(cData, 0, cData.Length - 4);

            byte[] fData = oStream.ToArray();

            if (_enc)
            {
                byte[] eData = new byte[fData.Length];
                encryptor.ProcessBytes(fData, 0, fData.Length, eData, 0);
                fData = eData;
            }

            return fData;
        }

        public abstract PacketType GetType();
        public abstract void SetModule(byte inMod);
        public abstract byte GetModule();
    }
}
