using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using NexusToRServer.NET.Packets.Server;

namespace NexusToRServer.NET.Packets.Client
{
    class CharacterListRequest : TORGameClientPacket
    {
        UInt16 _unk01, _unk02;

        /// <summary>
        /// Reads and Parses the information stored in the Packet
        /// </summary>
        public override void ReadImplementation()
        {
            ReadUInt32(); // Packet Type
            _unk01 = ReadUInt16();
            _unk02 = ReadUInt16();
        }

        /// <summary>
        /// Runs the final Packet Implementation
        /// </summary>
        public override void RunImplementation()
        {
            GetClient().SendPacket(new CharacterListReply(_unk01, _unk02));
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.CharacterListRequest;
        }
    }
}
