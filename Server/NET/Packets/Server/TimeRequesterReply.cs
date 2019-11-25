using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class TimeRequesterReply : TORGameServerPacket
    {
        private byte _module;

        public TimeRequesterReply()
        {
            //
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0x00010006); // Packet Component

            WriteString("localhost"); // Host
            WriteUInt32(20066); // Port

            WriteUInt32(0x14);
            WriteUInt64(0x00);
            WriteUInt64(0x00);
            WriteUInt32(0x00);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.TimeRequesterReply;
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
