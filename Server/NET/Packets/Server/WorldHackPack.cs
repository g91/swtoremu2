using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace NexusToRServer.NET.Packets.Server
{
    class WorldHackPack : TORGameServerPacket
    {
        private byte _module;

        public WorldHackPack()
        {
            //
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0x000329ED); // Packet Component

            // TODO: Properly implement this
            WriteUInt32(0x00000230);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000001);
            WriteUInt32(0x00000005);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000001);
            WriteUInt32(0x00000003);
            WriteUInt32(0x00000019);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000022);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000010);
            WriteUInt32(0x00000003);
            WriteUInt32(0x00000003);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000001);
            WriteUInt32(0x00000004);
            WriteUInt32(0x00000004);
            WriteUInt32(0x00000000);
            WriteUInt32(0x0000001A);
            WriteUInt32(0x00000005);
            WriteUInt32(0x00000005);
            WriteUInt32(0x00000002);
            WriteUInt32(0x0000000C);
            WriteUInt32(0x00000006);
            WriteUInt32(0x00000006);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000008);
            WriteUInt32(0x00000007);
            WriteUInt32(0x00000007);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000009);
            WriteUInt32(0x00000007);
            WriteUInt32(0x00000008);
            WriteUInt32(0x00000002);
            WriteUInt32(0x0000000A);
            WriteUInt32(0x00000009);
            WriteUInt32(0x00000009);
            WriteUInt32(0x00000000);
            WriteUInt32(0x0000001B);
            WriteUInt32(0x0000000A);
            WriteUInt32(0x0000000A);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000003);
            WriteUInt32(0x0000000A);
            WriteUInt32(0x0000000B);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000020);
            WriteUInt32(0x0000000B);
            WriteUInt32(0x0000000C);
            WriteUInt32(0x00000003);
            WriteUInt32(0x0000001E);
            WriteUInt32(0x0000000C);
            WriteUInt32(0x0000000C);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000016);
            WriteUInt32(0x0000000D);
            WriteUInt32(0x0000000D);
            WriteUInt32(0x00000001);
            WriteUInt32(0x00000021);
            WriteUInt32(0x0000000E);
            WriteUInt32(0x0000000E);
            WriteUInt32(0x00000000);
            WriteUInt32(0x0000001D);
            WriteUInt32(0x0000000F);
            WriteUInt32(0x0000000F);
            WriteUInt32(0x00000000);
            WriteUInt32(0x0000000B);
            WriteUInt32(0x00000010);
            WriteUInt32(0x00000010);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000018);
            WriteUInt32(0x00000011);
            WriteUInt32(0x00000011);
            WriteUInt32(0x00000001);
            WriteUInt32(0x00000007);
            WriteUInt32(0x00000012);
            WriteUInt32(0x00000012);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000015);
            WriteUInt32(0x00000012);
            WriteUInt32(0x00000012);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000011);
            WriteUInt32(0x00000013);
            WriteUInt32(0x00000014);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000014);
            WriteUInt32(0x00000016);
            WriteUInt32(0x00000001);
            WriteUInt32(0x0000000F);
            WriteUInt32(0x00000017);
            WriteUInt32(0x00000017);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000017);
            WriteUInt32(0x00000017);
            WriteUInt32(0x00000018);
            WriteUInt32(0x00000003);
            WriteUInt32(0x00000006);
            WriteUInt32(0x00000019);
            WriteUInt32(0x0000001A);
            WriteUInt32(0x00000003);
            WriteUInt32(0x0000001C);
            WriteUInt32(0x0000001A);
            WriteUInt32(0x0000001A);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000014);
            WriteUInt32(0x0000001B);
            WriteUInt32(0x0000001B);
            WriteUInt32(0x00000000);
            WriteUInt32(0x00000013);
            WriteUInt32(0x0000001C);
            WriteUInt32(0x0000001C);
            WriteUInt32(0x00000000);
            WriteUInt32(0x0000001F);
            WriteUInt32(0x0000001C);
            WriteUInt32(0x0000001C);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000012);
            WriteUInt32(0x0000001D);
            WriteUInt32(0x0000001E);
            WriteUInt32(0x00000001);
            WriteUInt32(0x0000000E);
            WriteUInt32(0x0000001E);
            WriteUInt32(0x0000001E);
            WriteUInt32(0x00000002);
            WriteUInt32(0x00000004);
            WriteUInt32(0x0000001F);
            WriteUInt32(0x0000001F);
            WriteUInt32(0x00000000);
            WriteUInt32(0x0000000D);
            WriteUInt32(0x0000001F);
            WriteUInt32(0x0000001F);
            WriteUInt32(0x00000002);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.WorldHackPack;
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
