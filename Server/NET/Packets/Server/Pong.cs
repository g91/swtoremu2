using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class Pong : TORGameServerPacket
    {
        private byte _module;
        private UInt32 _pingID;

        public Pong(UInt32 PingID)
        {
            //
            _module = 0x02;
            _pingID = PingID;
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32(_pingID); // Packet Type
            WriteUInt32(0x00000000); // Packet Component

            WriteString("");
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.Pong;
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
