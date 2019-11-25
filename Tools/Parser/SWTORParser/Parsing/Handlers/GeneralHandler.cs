using System.Text;

using SWTORParser.Classes;
using SWTORParser.Extensions;

namespace SWTORParser.Parsing.Handlers
{
    public static partial class Handlers
    {
        [Parser(Opcode.SetTrackingInfo)]
        public static StringBuilder HandleSetTrackingInfo(Packet packet)
        {
            return new StringBuilder().AppendLine("State", packet.Reader.ReadUInt64()).AppendLine("Unk1", packet.Reader.ReadUInt64()).AppendLine("Game State", packet.Reader.ReadString(true, false));
        }

        [Parser(Opcode.LogDebug)]
        public static StringBuilder HandleLogDebug(Packet packet)
        {
            return new StringBuilder().AppendLine("Debug", packet.Reader.ReadString(true));
        }

        [Parser(Opcode.UnkKey)]
        public static StringBuilder HandleUnkKey(Packet packet)
        {
            return new StringBuilder(512).AppendLine("Key", Encoding.UTF8.GetString(packet.Reader.ReadBytes(512)));
        }

        [Parser(Opcode.ClientHello)]
        [Parser(Opcode.CharacterListRequest)]
        public static StringBuilder HandleEmptyPacket(Packet packet)
        {
            return new StringBuilder();
        }

        [Parser(Opcode.GameSystemNotifyID)]
        public static StringBuilder HandleGameSystemNotifyID(Packet packet)
        {
            return new StringBuilder().AppendLine("Unk Long", packet.Reader.ReadUInt64());
        }

        [Parser(Opcode.TrackingServerInit)]
        public static StringBuilder HandleTrackingServerInit(Packet packet)
        {
            return new StringBuilder().AppendLine("Unk Byte", packet.Reader.ReadByte());
        }

        [Parser(Opcode.CMsg8EB28DE9)]
        public static StringBuilder HandleCMsg8Eb28De9(Packet packet)
        {
            var sb = new StringBuilder();

            var reader = ReadFrame(packet.Reader, sb);
            if (reader.CanRead(1))
            {

            }

            return sb;
        }


        [Parser(Opcode.HackNotifyData)]
        public static StringBuilder HandleHackNotifyData(Packet packet)
        {
            var sb = new StringBuilder();

            var reader = ReadFrame(packet.Reader, sb);
            if (reader.CanRead(1))
            {
                
            }

            return sb;
        }

        [Parser(Opcode.ModulesList)]
        public static StringBuilder HandleModulesList(Packet packet)
        {
            var sb = new StringBuilder();

            var reader = ReadFrame(packet.Reader, sb);
            if (reader.CanRead(1))
            {
                var reader2 = ReadFrame(reader, sb);
                if (reader2.CanRead(1))
                {
                    
                }
            }

            return sb;
        }
    }
}
