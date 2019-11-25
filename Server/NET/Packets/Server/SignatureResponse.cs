using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class SignatureResponse : TORGameServerPacket
    {
        private byte _module;

        private string _sig, _hash;
        private int _ep;
        private UInt16 _unk01, _unk02;

        public SignatureResponse(UInt16 Unk01, UInt16 Unk02, string Sig, int EntryPoint, string Hash)
        {
            //
            _unk01 = Unk01;
            _unk02 = Unk02;
            _sig = Sig;
            _ep = EntryPoint;
            _hash = Hash;
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0xFFFFFFFF); // Packet Component
            WriteUInt16(_unk01);
            WriteUInt16(_unk02);
            WriteString(_sig);
            WriteString("userentrypoint" + _ep.ToString());
            WriteString(_hash);
            WriteUInt64(0x00);
            WriteString("");
            WriteString("");
            WriteUInt64(0x00);

        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.SignatureResponse;
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
