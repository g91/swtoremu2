using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class ObjectRequest : TORGameServerPacket
    {
        private byte _module;

        private string _obj;
        private byte _unk01;
        private UInt64 _unk02;

        public ObjectRequest(string Object, Byte Unk01, UInt64 Unk02)
        {
            //
            _obj = Object;
            _unk01 = Unk01;
            _unk02 = Unk02;
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0xFFFFFFFF); // Packet Component
            //WriteByte(_unk01);
            WriteString(_obj);
            WriteUInt64(_unk02);
            WriteUInt32(0x00);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.ObjectRequest;
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
