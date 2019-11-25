using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using NexusToRServer.NET.Packets.Server;

namespace NexusToRServer.NET.Packets.Client
{
    class RequestClose : TORGameClientPacket
    {
        /// <summary>
        /// Reads and Parses the information stored in the RequestClose
        /// </summary>
        public override void ReadImplementation()
        {
            ReadUInt32(); // Packet Type
            ReadUInt32(); // Packet Component
        }

        /// <summary>
        /// Runs the final RequestClose Implementation
        /// </summary>
        public override void RunImplementation()
        {

        }

        /// <summary>
        /// Returns the PacketType of the specified RequestClose
        /// </summary>
        /// <returns>PacketType of specified RequestClose</returns>
        public override PacketType GetType()
        {
            return PacketType.Null;
        }
    }
}
