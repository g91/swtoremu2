using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class AreaTeleportCharacter : TORGameServerPacket
    {
        private byte _module;
        private UInt64 _chID;
        private UInt32 _type;
        private Byte _unk01;
        private Single _x1, _y1, _z1, _x2, _y2, _z2;

        public AreaTeleportCharacter(UInt64 CharID, UInt32 TeleType, Single X1, Single Y1, Single Z1, Single X2, Single Y2, Single Z2, Byte Unk01 )
        {
            //
            _chID = CharID;
            _type = TeleType;
            _x1 = X1;
            _y1 = Y1; 
            _z1 = Z1;
            _x2 = X2;
            _y2 = Y2;
            _z2 = Z2;
            _unk01 = Unk01;
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0x00040000); // Packet Component

            WriteUInt64(_chID);
            WriteUInt32(_type);
            WriteFloat(_x1);
            WriteFloat(_y1);
            WriteFloat(_z1);
            WriteFloat(_x2);
            WriteFloat(_y2);
            WriteFloat(_z2);
            WriteByte(_unk01);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.AreaTeleportCharacter;
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
