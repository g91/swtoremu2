﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class WorldTravelPending : TORGameServerPacket
    {
        private byte _module;
        private UInt16 _unk01, _unk02;

        public WorldTravelPending(UInt16 Unk01, UInt16 Unk02)
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

            WriteString("tython_blockout");
            WriteString("4611686019869492753");
            WriteUInt32(0x55F4C611);
            WriteUInt32(0x40000000);
            WriteUInt32(0x01);
            WriteUInt32(0x00);
            WriteString(@"\world\areas\4611686019869492753\area.dat");
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.WorldTravelPending;
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
