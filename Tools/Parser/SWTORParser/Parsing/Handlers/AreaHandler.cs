using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SWTORParser.Classes;
using SWTORParser.Extensions;

namespace SWTORParser.Parsing.Handlers
{
    public static partial class Handlers
    {
        [Parser(Opcode.AreaAwarenessEntered)]
        public static StringBuilder HandlerAreaAwarenessEntered(Packet packet)
        {
            var sb = new StringBuilder();

            ReadFrame(packet.Reader, sb);

            //ReadUnkValues(packet.Reader, sb, 5);

            return sb;
        }

        [Parser(Opcode.AreaModulesList)]
        public static StringBuilder HandleAreaModulesList(Packet packet)
        {
            return new StringBuilder();
        }

        [Parser(Opcode.AreaTeleportCharacter)]
        public static StringBuilder HandleAreaTeleportCharacter(Packet packet)
        {
            var sb = new StringBuilder().AppendLine("Unk Guid", packet.Reader.ReadUInt64()).AppendLine("Unk Val (Maybe MapId)", packet.Reader.ReadUInt32());
            sb.AppendLine("X", packet.Reader.ReadSingle()).AppendLine("Y", packet.Reader.ReadSingle()).AppendLine("Z", packet.Reader.ReadSingle());
            sb.AppendLine("Rot1", packet.Reader.ReadSingle()).AppendLine("Rot2", packet.Reader.ReadSingle()).AppendLine("Rot3", packet.Reader.ReadSingle());
            return sb.AppendLine("Unk Byte", packet.Reader.ReadByte());
        }

        [Parser(Opcode.AreaSendAwarenessRange)]
        public static StringBuilder HandleAreaSendAwarenessRange(Packet packet)
        {
            return new StringBuilder().AppendLine("Awareness Range", packet.Reader.ReadSingle()).AppendLine("Hysteresis Range", packet.Reader.ReadSingle());
        }

        [Parser(Opcode.AreaRequestRPC)]
        public static StringBuilder HandleAreaRequestRPC(Packet packet)
        {
            var sb = new StringBuilder();

            var reader = ReadFrame(packet.Reader, sb);

            sb.AppendLine("Procedure Id", ReadLengthedDataFromStream(reader, 5));
            while (reader.CanRead(1))
            {
                var t = reader.ReadByte();
                switch (t)
                {
                    case 6:
                        sb.AppendLine("Unk String", Encoding.UTF8.GetString(packet.Reader.ReadBytes((Int32) ReadLengthedDataFromStream(reader, 5))));
                        break;

                    default:
                        sb.AppendLine("unkTypeasd", t);
                        break;
                }
            }

            return sb;
        }

        [Parser(Opcode.AreaClientReplicationTransaction)]
        public static StringBuilder HandleAreaClientReplicationTransaction(Packet packet)
        {
            var sb = new StringBuilder().AppendLine("Unk Val", packet.Reader.ReadUInt32());
            return sb;
            ReadFrame(packet.Reader, sb);
            var reader = packet.Reader;
            {
                const Byte type = 5;
                var flags = reader.ReadByte();

                if ((flags & 1) != 0)
                {
                    var count = ReadLengthedDataFromStream(reader, type);

                    for (var i = 0UL; i < count; ++i)
                    {
                        sb.AppendLine().AppendFormat("Object #{0}{1}", i + 1, Environment.NewLine).AppendLine("    Node Id", ReadLengthedDataFromStream(reader, type));

                        var cflags = reader.ReadByte();
                        sb.AppendLine("    Flags", flags);

                        if ((cflags & 0x80) != 0)
                            sb.AppendLine("    Class Id", ReadLengthedDataFromStream(reader, type));

                        if ((cflags & 0x40) != 0)
                            sb.AppendLine("    Template Id", ReadLengthedDataFromStream(reader, type));

                        if ((cflags & 0x20) != 0)
                            sb.AppendLine("    Parent Node Id", ReadLengthedDataFromStream(reader, type));

                        if ((cflags & 0x10) != 0)
                        {
                            var c = reader.ReadByte();
                            sb.AppendLine().AppendLine("    Unk Byte", c);

                            if ((c & 0x1) != 0 || (c & 0x2) != 0)
                            {
                                var countt = reader.ReadUInt32();
                                sb.AppendLine("    Unk Count", countt);

                                for (var j = 0U; j < countt; ++j)
                                    sb.AppendLine(String.Format("        Unk Guid #{0}", j), reader.ReadUInt64());
                            }
                        }

                        if ((cflags & 0x08) == 0)
                            continue;

                        var sbs = new StringBuilder();

                        ReadFields(reader, sbs, type);

                        sb.Append(sbs.ToString().Replace(Environment.NewLine, String.Format("    {0}", Environment.NewLine)));
                    }
                }

                if ((flags & 2) == 0)
                    return sb;

                if (type <= 1)
                {
                    var cou = 0UL;
                    var by = reader.ReadByte();
                    if (by == 135)
                        cou = ReadLengthedDataFromStream(reader, type);

                    for (UInt64 i = 0; i < cou; ++i)
                        sb.AppendLine(String.Format("Unk Val #{0}", i), ReadLengthedDataFromStream(reader, type));
                }
                else
                {
                    var cou = ReadLengthedDataFromStream(reader, type);
                    sb.AppendLine().AppendLine("Val count", cou);

                    for (UInt64 i = 0; i < cou; ++i)
                        sb.AppendLine(String.Format("Unk Val #{0}", i), ReadLengthedDataFromStream(reader, type));
                }
            }

            return sb;
        }

        [Parser(Opcode.AreaUpdateTimeSource)]
        public static StringBuilder HandleAreaUpdateTimeSource(Packet packet)
        {
            return new StringBuilder().AppendLine("Unk Long", packet.Reader.ReadUInt64()).AppendLine("Unk Long 2", packet.Reader.ReadUInt64());
        }

        [Parser(Opcode.AreaHackPack)]
        public static StringBuilder HandleAreaHackPack(Packet packet)
        {
            var sb = new StringBuilder();

            var reader = ReadFrame(packet.Reader, sb);
            if (reader.CanRead(1))
            {
                
            }

            return sb;
        }
    }
}
