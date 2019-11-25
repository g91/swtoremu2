using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class WorldNotifyGauntletVersion : TORGameServerPacket
    {
        private byte _module;

        public WorldNotifyGauntletVersion()
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
            WriteUInt32(0x11);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.WorldNotifyGauntletVersion;
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
