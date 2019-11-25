using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class WorldSendToArea : TORGameServerPacket
    {
        private byte _module;
        private UInt16 _unk01, _unk02;

        public WorldSendToArea(UInt16 Unk01, UInt16 Unk02)
        {
            //
            _unk01 = Unk01;
            _unk02 = Unk02;
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt16(_unk01);
            WriteUInt16(_unk02);

            WriteString("AreaServer-tython_blockout-4611686019869492753-1-:areaserver");
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.WorldSendToArea;
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
