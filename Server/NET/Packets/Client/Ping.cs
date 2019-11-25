using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using NexusToRServer.NET.Packets.Server;

namespace NexusToRServer.NET.Packets.Client
{
    class Ping : TORGameClientPacket
    {
        UInt32 _pingID;

        /// <summary>
        /// Reads and Parses the information stored in the Packet
        /// </summary>
        public override void ReadImplementation()
        {
            _pingID = ReadUInt32(); // Packet Type
            ReadUInt32(); // Packet Component
        }

        /// <summary>
        /// Runs the final Packet Implementation
        /// </summary>
        public override void RunImplementation()
        {
            GetClient().SendPacket(new Pong(_pingID));
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.Ping;
        }
    }
}
