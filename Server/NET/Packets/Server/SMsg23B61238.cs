using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class SMsg23B61238 : TORGameServerPacket
    {
        private byte _module;
        private UInt32 _unk01;
        private byte[] _blob;

        public SMsg23B61238(UInt32 Unk01, byte[] Blob)
        {
            //
            _unk01 = Unk01;
            _blob = Blob;
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0x00040000); // Packet Component

            WriteUInt32(_unk01);
            WriteInt32(_blob.Length);
            WriteBytes(_blob);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.SMsg23B61238;
        }

        public override void SetModule(byte inMod)
        {
            _module = inMod;
        }

        public override byte GetModule()
        {
            return _module;
        }
    }
}
