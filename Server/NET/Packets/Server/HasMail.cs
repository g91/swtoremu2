using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class HasMail : TORGameServerPacket
    {
        private byte _module;
        private UInt32 _msgCount, _msgRead;
        private Boolean _unk01;

        public HasMail(UInt64 CharID)
        {
            // TODO: Lookup for mail by charID
            _msgCount = 0x03;
            _msgRead = 0x03;
            _unk01 = false;
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0x00080000); // Packet Component

            WriteUInt32(_msgCount);
            WriteUInt32(_msgRead);
            WriteBoolean(_unk01);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.HasMail;
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
