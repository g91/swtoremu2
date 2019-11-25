using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class WorldRequestRPC : TORGameServerPacket
    {
        private byte _module;

        public WorldRequestRPC()
        {
            //
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0x000329ED); // Packet Component

            WriteUInt32(0x0E);
            WriteBytes(new byte[] { 0xCF, 0x2B, 0x7E, 0x42, 0x02, 0xFD, 0x47, 0xB4, 0xD7, 0x01, 0xCA, 0x24, 0xE3, 0x75 }); // Static data
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.WorldRequestRPC;
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
