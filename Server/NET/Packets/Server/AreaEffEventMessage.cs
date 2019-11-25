using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class AreaEffEventMessage : TORGameServerPacket
    {
        private byte _module;
        private byte[] _aeff;

        public AreaEffEventMessage(String Area, String AreaID, String AreaCode, int EffectID)
        {
            //
            _aeff = AreaServer.EffectEvents.Get(Area, AreaID, AreaCode, EffectID);
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0x00040000); // Packet Component

            WriteInt32(_aeff.Length);
            WriteBytes(_aeff);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.AreaEffEventMessage;
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
