using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class ClientReplicationTransaction : TORGameServerPacket
    {
        private byte _module;
        private UInt32 _transID, _frame;
        private byte[] _data;


        public ClientReplicationTransaction(UInt32 TransID, UInt32 Frame, byte[] Data)
        {
            _transID = TransID;
            _frame = Frame;
            _data = Data;
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0x000529F2); // Packet Component
            WriteUInt32(_transID);
            WriteUInt32(_frame);
            WriteBytes(_data);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.ClientReplicationTransaction;
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
