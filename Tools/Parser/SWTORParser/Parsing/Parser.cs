using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Microsoft.Win32;

using SWTORParser.Classes;
using SWTORParser.Extensions;
using SWTORParser.Forms;

namespace SWTORParser.Parsing
{
    public static class Parser
    {
        private static readonly Dictionary<Opcode, Func<Packet, StringBuilder>> Handlers = new Dictionary<Opcode, Func<Packet, StringBuilder>>();

        public static StreamWriter OutStream;

        static Parser()
        {
            var asm = Assembly.GetExecutingAssembly();
            var types = asm.GetTypes();

            foreach (var type in types)
            {
                if (!type.IsClass || !type.IsPublic)
                    continue;

                var methods = type.GetMethods();

                foreach (var method in methods)
                {
                    if (!method.IsPublic)
                        continue;

                    var attrs = (ParserAttribute[])method.GetCustomAttributes(typeof(ParserAttribute), false);

                    if (attrs.Length <= 0)
                        continue;

                    var parms = method.GetParameters();

                    if (parms.Length <= 0)
                        continue;

                    if (parms[0].ParameterType != typeof(Packet))
                        continue;

                    foreach (var opc in attrs.Select(attr => attr.Opcode))
                        Handlers[opc] = (Func<Packet, StringBuilder>)Delegate.CreateDelegate(typeof(Func<Packet, StringBuilder>), method);
                }
            }
        }

        public static void SaveFile()
        {
            var sfd = new SaveFileDialog
            {
                InitialDirectory = MainWindow.LastFolder,
                Filter = "Text File|*.txt"
            };
            sfd.FileOk += (sender, args) => OutStream = new StreamWriter(sfd.FileName) { AutoFlush = true };
            sfd.ShowDialog();
        }

        public static void Parse(Packet packet)
        {
            var opc = (Opcode)Enum.Parse(typeof(Opcode), packet.PacketID.ToString(CultureInfo.InvariantCulture));
            var smsg = packet.FromServer; // OpcodeHelper.IsServerMessage(opc);

            if (opc == Opcode.Ping && smsg)
                opc = Opcode.Pong;

            var opcS = opc.ToString().PadRight(32);
            var opcH = packet.PacketID.ToString("X8");

            var datLen = packet.Data.Length - 8;

            var sI = smsg ? "S -> C" : "C -> S";

            var contVer = packet.ContentVersion.ToString(CultureInfo.InvariantCulture).PadLeft(5);
            var tranVer = packet.TransportVersion.ToString(CultureInfo.InvariantCulture).PadLeft(5);

            String toW;
            var pad = "";

            if (!Handlers.ContainsKey(opc))
            {
                var data = new Byte[datLen];
                Array.Copy(packet.Data, 8, data, 0, datLen);
                toW = data.ToHEX();
            }
            else
            {
                var sb = Handlers[opc](packet);

                if (!packet.Reader.IsFinal())
                {
                    var data = packet.Reader.ReadBytes((Int32)packet.Reader.Remaining());

                    sb.AppendLine().AppendLine("Remaining Data Length", data.Length).AppendLine("Remaining Data", BitConverter.ToString(data).Replace("-", " "));
                }

                sb.Replace(Environment.NewLine, String.Format("{0}    ", Environment.NewLine));

                toW = sb.ToString();
                pad = "    ";
            }

            var content = String.Format(@"{0} | Opcode: {1} (0x{2}) | Module: {9} | Content Version: {10} | Transport Version: {8} | Len: {3}{4}{6} -->{4}{4}{11}{5}{4}{7} <--{4}{4}", sI, opcS, opcH, datLen.ToString(CultureInfo.InvariantCulture).PadLeft(5), Environment.NewLine, toW, "{", "}", tranVer, packet.Module, contVer, pad);

            OutStream.WriteLine(content);
        }
    }
}
