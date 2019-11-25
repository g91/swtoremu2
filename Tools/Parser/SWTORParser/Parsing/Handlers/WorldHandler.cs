using System;
using System.IO;
using System.Text;

using MiscUtil.Conversion;

using SWTORParser.Classes;
using SWTORParser.Extensions;

namespace SWTORParser.Parsing.Handlers
{
    public static partial class Handlers
    {
        [Parser(Opcode.WorldTravelPending)]
        public static StringBuilder HandleWorldTravelPending(Packet packet)
        {
            return new StringBuilder().AppendLine("Zone", packet.Reader.ReadString(true)).AppendLine("Unk1", packet.Reader.ReadString(true))
                .AppendLine("Unk2", packet.Reader.ReadUInt32()).AppendLine("Unk3", packet.Reader.ReadUInt32()).AppendLine("Unk4", packet.Reader.ReadUInt32())
                .AppendLine("Unk5", packet.Reader.ReadUInt32()).AppendLine("Unk6", packet.Reader.ReadString(true));
        }

        [Parser(Opcode.WorldTravelStatus)]
        public static StringBuilder HandleWorldTravelStatus(Packet packet)
        {
            return new StringBuilder().AppendLine("Unk", packet.Reader.ReadUInt32());
        }

        [Parser(Opcode.WorldShouldSendScriptErrors)]
        public static StringBuilder HandleWorldShouldSendScriptErrors(Packet packet)
        {
            return new StringBuilder().AppendLine("Should send", packet.Reader.ReadBoolean());
        }

        [Parser(Opcode.WorldSendToArea)]
        public static StringBuilder HandleWorldSendToArea(Packet packet)
        {
            return new StringBuilder().AppendLine("Unk", packet.Reader.ReadString(true));
        }

        [Parser(Opcode.WorldRequestRPC)]
        public static StringBuilder HandleWorldRequestRpc(Packet packet)
        {
            return new StringBuilder().AppendLine("Unk", packet.Reader.ReadUInt32()).AppendLine("UnkArr", BitConverter.ToString(packet.Reader.ReadBytes((Int32)packet.Reader.Remaining())).Replace("-", " "));
        }

        [Parser(Opcode.WorldNotifyGauntletVersion)]
        public static StringBuilder HandleWorldNotifyGauntletVersion(Packet packet)
        {
            return new StringBuilder().AppendLine("Unk", packet.Reader.ReadUInt32());
        }

        [Parser(Opcode.WorldHackPack)]
        public static StringBuilder HandleWorldHackPack(Packet packet)
        {
            var sb = new StringBuilder();

            var reader = ReadFrame(packet.Reader, sb);
            if (reader.CanRead(1))
            {
                // TODO structure
            }

            return sb;
        }
    }
}
