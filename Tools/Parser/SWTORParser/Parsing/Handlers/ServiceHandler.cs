using System.Globalization;
using System.IO;
using System.Text;

using SWTORParser.Classes;
using SWTORParser.Extensions;

namespace SWTORParser.Parsing.Handlers
{
    public static partial class Handlers
    {
        [Parser(Opcode.ServiceRequest)]
        public static StringBuilder HandleServiceRequest(Packet packet)
        {
            return new StringBuilder().AppendLine("Server Type", packet.Reader.ReadString(true)).AppendLine("Service Name", packet.Reader.ReadString(true))
                    .AppendLine("Unk1", packet.Reader.ReadString(true)).AppendLine("Unk2", packet.Reader.ReadString(true)).AppendLine("Service Object Name", packet.Reader.ReadString(true))
                    .AppendLine("Padding", packet.Reader.ReadString(true)).AppendLine("Hash", packet.Reader.ReadString(true));
        }

        [Parser(Opcode.ObjectRequest)]
        public static StringBuilder HandleObjectRequest(Packet packet)
        {
            return new StringBuilder().AppendLine("Object Name", packet.Reader.ReadString(true)).AppendLine("Unk Long", packet.Reader.ReadUInt64()).AppendLine("Unk Int", packet.Reader.ReadUInt32());
        }

        [Parser(Opcode.ObjectReply)]
        public static StringBuilder HandleObjectReply(Packet packet)
        {
            return new StringBuilder().AppendLine("Service Id", packet.Reader.ReadUInt16()).AppendLine("Service Object Name", packet.Reader.ReadString(true))
                .AppendLine("Hash", packet.Reader.ReadString(true)).AppendLine("Origin", packet.Reader.ReadString(true)).AppendLine("Timestamp", packet.Reader.ReadUInt64());
        }

        [Parser(Opcode.ClientInformation)]
        public static StringBuilder HandleClientInformation(Packet packet)
        {
            return new StringBuilder().AppendLine("Unk Int1", packet.Reader.ReadUInt32()).AppendLine("XML", packet.Reader.ReadString(true));
        }

        [Parser(Opcode.ConnectionHandshake)]
        public static StringBuilder HandleConnectionHandshake(Packet packet)
        {
            // TODO
            return new StringBuilder();
        }

        [Parser(Opcode.RequestMultipleRPC)]
        public static StringBuilder HandleRequestMultipleRPC(Packet packet)
        {
            var sb = new StringBuilder();
            var frameCount = packet.Reader.ReadUInt32();
            sb.AppendLine("Frame Count", frameCount);

            for (var i = 0U; i < frameCount; ++i)
            {
                var reader = ReadFrame(packet.Reader, sb);
                if (reader.CanRead(1))
                {
                    
                }
            }

            return sb;
        }

        [Parser(Opcode.Ping)]
        [Parser(Opcode.Pong)]
        public static StringBuilder HandlePong(Packet packet)
        {
            return packet.Module == 2 ? new StringBuilder().AppendLine("Unk Int", packet.Reader.ReadUInt32()).AppendLine("Unk Byte", packet.Reader.ReadByte()) : new StringBuilder();
        }

        [Parser(Opcode.SignatureResponse)]
        public static StringBuilder HandleSignatureResponse(Packet packet)
        {
            return new StringBuilder().AppendLine("Unk Short", packet.Reader.ReadUInt16()).AppendLine("Unk Short", packet.Reader.ReadUInt16()).AppendLine("Unk String", packet.Reader.ReadString(true))
                .AppendLine("Unk String", packet.Reader.ReadString(true)).AppendLine("Unk String", packet.Reader.ReadString(true)).AppendLine("Unk Long", packet.Reader.ReadUInt64())
                .AppendLine("Unk String", packet.Reader.ReadString(true)).AppendLine("Unk String", packet.Reader.ReadString(true)).AppendLine("Unk Long", packet.Reader.ReadUInt64());
        }

        [Parser(Opcode.TimeRequesterReply)]
        public static StringBuilder HandleTimeRequesterReply(Packet packet)
        {
            var sb = new StringBuilder().AppendLine("Unk String", packet.Reader.ReadString(true)).AppendLine("Unk Int", packet.Reader.ReadUInt32());

            var count = packet.Reader.ReadUInt32();
            sb.AppendLine("Unk Count", count);

            for (var i = 0U; i < count; ++i)
                sb.AppendLine("    Unk Byte", packet.Reader.ReadByte());

            return sb;
        }
    }
}
