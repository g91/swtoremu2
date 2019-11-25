using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using NexusToRServer.NET.Packets.Server;
using System.Drawing;
using System.Drawing.Imaging;

namespace NexusToRServer.NET.Packets.Client
{
    class CreateCharacterRequest : TORGameClientPacket
    {
        /// <summary>
        /// Reads and Parses the information stored in the Packet
        /// </summary>
        public override void ReadImplementation()
        {
            ReadUInt32(); // Packet Type
            ReadUInt32(); // Packet Component

            TOR.Character nChar = new TOR.Character();

            nChar._name = ReadString();
            nChar._id = ReadUInt64();
            nChar._unk05 = ReadByte();

            if ((nChar._unk05 & 0x80) > 0)
                nChar._unk01 = ReadUInt64();

            if ((nChar._unk05 & 0x40) > 0)
                nChar._unk02 = ReadUInt64();

            if ((nChar._unk05 & 0x20) > 0)
            {
                nChar._unk03 = ReadUInt64();
                nChar._unk04 = ReadUInt64();
            }

            if ((nChar._unk05 & 0x10) > 0)
            {
                nChar._unk06 = ReadByte();
                UInt32 count = ReadUInt32();

                for (int i = 0; i < count; i++)
                    nChar.UnkList.Add(ReadUInt64());
            }

            if ((nChar._unk05 & 0x08) > 0)
            {
                nChar._unk08 = ReadUInt16();
                nChar._unk07 = ReadByte();

                Int32 bLength = ReadInt32();
                nChar.Blob = ReadBytes(bLength);
            }

            /*int charID = 0;
            while (File.Exists(String.Format("C:\\Nexus\\Packet Logs\\Character\\Char{0}.dat", charID)))
                charID++;

            Rectangle rect = new Rectangle(646, 116, 1024, 768);
            Bitmap bmp = new Bitmap(rect.Width, rect.Height, PixelFormat.Format32bppArgb);
            Graphics g = Graphics.FromImage(bmp);
            g.CopyFromScreen(rect.Left, rect.Top, 0, 0, bmp.Size, CopyPixelOperation.SourceCopy);
            bmp.Save(String.Format("C:\\Nexus\\Packet Logs\\Character\\Char{0}.png", charID), ImageFormat.Png);

            File.WriteAllBytes(String.Format("C:\\Nexus\\Packet Logs\\Character\\Char{0}.dat", charID), ReadBytes(this._buffer.Length - 8));*/
        }

        /// <summary>
        /// Runs the final Packet Implementation
        /// </summary>
        public override void RunImplementation()
        {
            //GetClient().ForceKill();
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.CreateCharacterRequest;
        }
    }
}
