using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using NexusToRServer.NET.Packets.Server;

namespace NexusToRServer.NET.Packets.Client
{
    class SetTrackingInfo : TORGameClientPacket
    {
        UInt64 _stateID, _unk01;
        String _gameState;

        /// <summary>
        /// Reads and Parses the information stored in the Packet
        /// </summary>
        public override void ReadImplementation()
        {
            ReadUInt32(); // Packet Type
            ReadUInt32(); // Packet Component

            _stateID = ReadUInt64();
            _unk01 = ReadUInt64();
            _gameState = ReadString();
        }

        /// <summary>
        /// Runs the final Packet Implementation
        /// </summary>
        public override void RunImplementation()
        {
            GetClient().TrackingInfo = _gameState;
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.SetTrackingInfo;
        }
    }
}
