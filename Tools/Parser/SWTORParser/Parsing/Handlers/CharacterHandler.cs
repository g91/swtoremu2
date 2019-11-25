using System;
using System.Globalization;
using System.IO;
using System.Text;
using MiscUtil.Conversion;
using SWTORParser.Classes;
using SWTORParser.Extensions;
using SWTORParser.Hero;

namespace SWTORParser.Parsing.Handlers
{
    public static partial class Handlers
    {
        [Parser(Opcode.DeleteCharacterRequest)]
        public static StringBuilder HandleCharacterDelete(Packet packet)
        {
            return new StringBuilder().AppendLine("Guid", packet.Reader.ReadUInt64());
        }

        [Parser(Opcode.CreateCharacterRequest)]
        public static StringBuilder HandleCharacterCreate(Packet packet)
        {
            var sb = new StringBuilder().AppendLine("Name", packet.Reader.ReadString(true)).AppendLine(
                "Guid", packet.Reader.ReadUInt64());

            var flags = packet.Reader.ReadByte();
            sb.AppendLine("Flags", flags);

            if ((flags & 0x80) != 0)
                sb.AppendLine("Class Id", packet.Reader.ReadUInt64());

            if ((flags & 0x40) != 0)
                sb.AppendLine("Template Id", packet.Reader.ReadUInt64());

            if ((flags & 0x20) != 0)
            {
                sb.AppendLine("Parent Node Id1", packet.Reader.ReadUInt64());
                sb.AppendLine("Parent Node Id2", packet.Reader.ReadUInt64());
            }

            if ((flags & 0x10) != 0)
            {
                var unkbyte = packet.Reader.ReadByte();
                sb.AppendLine("Unk Byte", unkbyte);

                if ((unkbyte & 0x1) != 0 || (unkbyte & 0x2) != 0)
                {
                    var count = packet.Reader.ReadInt32();

                    sb.AppendLine().AppendLine("Unk Count", count);

                    for (int i = 1; i <= count; ++i)
                        sb.AppendLine(String.Format("    Unk Guid #{0}", i), packet.Reader.ReadUInt64());
                }
            }

            if ((flags & 0x08) != 0)
            {
                sb.AppendLine().AppendLine("Fields:");
                sb.AppendLine("    Version", packet.Reader.ReadUInt16());
                sb.AppendLine("    Format", packet.Reader.ReadByte());

                var count = packet.Reader.ReadUInt32();

                sb.AppendLine().AppendLine("    Fields Size", count);

                /*for (var i = 0U; i < count; ++i)
                {
                    var val = packet.Reader.ReadByte();
                    //sb.AppendFormat("    Field #{0}:    {1}    0x{2:X2}    {3}    {4}{5}", i.ToString().PadLeft(3, '0'), val.ToString().PadLeft(3, '0'), val, Convert.ToString(val, 2).PadLeft(8, '0'), val > 32 ? Convert.ToChar(val).ToString() : "", Environment.NewLine);
                    sb.AppendLine(String.Format("    Unk Val #{0}", i), val);
                }*/

                if (true)
                {
                    var c1 = ReadLengthedDataFromStream(packet.Reader, 5);
                    var c2 = ReadLengthedDataFromStream(packet.Reader, 5);

                    sb.AppendLine().AppendLine(String.Format("    Counter1: {0} | Counter2: {1}", c1, c2)).AppendLine();

                    for (var i = 0UL; i < c2; ++i)
                    {
                        var fieldId = ReadLengthedDataFromStream(packet.Reader, 5);
                        var type = ReadLengthedDataFromStream(packet.Reader, 5);
                        var data = "";

                        switch (type)
                        {
                            case 1:
                            case 5:
                            case 14:
                            case 15:
                            case 16:
                            case 19:
                                data = ReadLengthedDataFromStream(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);
                                break;

                            case 2:
                                data = ReadLengthedDataFromStream2(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);
                                break;

                            case 18:
                                data = String.Format("X: {0} | Y: {1} | Z: {2}", packet.Reader.ReadSingle(), packet.Reader.ReadSingle(), packet.Reader.ReadSingle());
                                break;

                            case 6:
                                data = Encoding.UTF8.GetString(packet.Reader.ReadBytes((Int32)ReadLengthedDataFromStream(packet.Reader, 5)));
                                break;

                            case 7:
                                {
                                    var ltype = ReadLengthedDataFromStream(packet.Reader, 5);
                                    /*var lc1 = */ReadLengthedDataFromStream(packet.Reader, 5);
                                    var lc2 = ReadLengthedDataFromStream(packet.Reader, 5);

                                    HeroTypes tE;
                                    Enum.TryParse(ltype.ToString(CultureInfo.InvariantCulture), out tE);

                                    var sbs = new StringBuilder(String.Format("{2}    List of {0} | Count: {1}", tE, lc2, Environment.NewLine)).AppendLine();

                                    for (var j = 0UL; j < lc2; ++j)
                                    {
                                        var ind = ReadLengthedDataFromStream(packet.Reader, 5);
                                        var ldata = ReadLengthedDataFromStream(packet.Reader, 5);

                                        sbs.AppendLine(String.Format("        Ind: {0} | Data: {1}", ind, ldata));
                                    }

                                    data = sbs.ToString();
                                }
                                break;

                            case 8:
                                {
                                    var lType = ReadLengthedDataFromStream(packet.Reader, 5);
                                    var lValT = ReadLengthedDataFromStream(packet.Reader, 5);

                                    /*var lc1 = */ReadLengthedDataFromStream(packet.Reader, 5);
                                    var lc2 = ReadLengthedDataFromStream(packet.Reader, 5);

                                    HeroTypes lE, lV;
                                    Enum.TryParse(lType.ToString(CultureInfo.InvariantCulture), out lE);
                                    Enum.TryParse(lValT.ToString(CultureInfo.InvariantCulture), out lV);

                                    var sbs = new StringBuilder(String.Format("{3}    Lookup List of {0} | ValT: {1} | Count: {2}", lE, lV, lc2, Environment.NewLine)).AppendLine();

                                    for (var j = 0UL; j < lc2; ++j)
                                    {
                                        var ind = ReadLengthedDataFromStream(packet.Reader, 5);
                                        var ldata = ReadLengthedDataFromStream(packet.Reader, 5);

                                        sbs.AppendLine(String.Format("        Ind: {0} | Data: {1}", ind, ldata));
                                    }

                                    data = sbs.ToString();
                                }
                                break;
                        }
                        sb.AppendLine(String.Format("    F Id: {0} | Type: {1} | Data: {2}", fieldId, type, data));
                        //var data = ReadLengthedDataFromStream(packet.Reader, 5);
                    }
                }

                /*var sbs = new StringBuilder();
                ReadFields(packet.Reader, sbs);
                sb.AppendLine(sbs.ToString().Replace(Environment.NewLine, String.Format("{0}    ", Environment.NewLine)));*/
            }
            return sb;
        }

        [Parser(Opcode.SelectCharacterRequest)]
        public static StringBuilder HandleCharacterSelect(Packet packet)
        {
            return new StringBuilder().AppendLine("Guid", packet.Reader.ReadUInt64());
        }

        [Parser(Opcode.CharacterListReply)]
        public static StringBuilder HandleCharacterListSmsg(Packet packet)
        {
            var count = packet.Reader.ReadUInt32();
            var sb = new StringBuilder().AppendLine("Character Count", count).AppendLine();

            for (UInt32 i = 0; i < count; ++i)
            {
                var sbs = new StringBuilder().AppendLine(String.Format("Character #{0}", i + 1)).AppendLine("Character Guid", packet.Reader.ReadUInt64());

                var flags = packet.Reader.ReadByte();
                sbs.AppendLine("Flags", flags);

                if ((flags & 0x80) != 0)
                    sbs.AppendLine("Class Id", packet.Reader.ReadUInt64());

                if ((flags & 0x40) != 0)
                    sbs.AppendLine("Template Id", packet.Reader.ReadUInt64());

                if ((flags & 0x20) != 0)
                {
                    sbs.AppendLine("Parent Node Id1", packet.Reader.ReadUInt64());
                    sbs.AppendLine("Parent Node Id2", packet.Reader.ReadUInt64());
                }

                if ((flags & 0x10) != 0)
                {
                    var unkbyte = packet.Reader.ReadByte();
                    sbs.AppendLine("Unk Byte", unkbyte);

                    if ((unkbyte & 0x1) != 0 || (unkbyte & 0x2) != 0)
                    {
                        var count2 = packet.Reader.ReadUInt32();

                        sbs.AppendLine().AppendLine("Unk Count", count2);

                        for (var j = 0U; j < count2; ++j)
                            sbs.AppendLine(String.Format("    Unk Guid #{0}", j), packet.Reader.ReadUInt64());
                    }
                }

                if ((flags & 0x08) != 0)
                {
                    sbs.AppendLine().AppendLine("Fields:");
                    sbs.AppendLine("Version", packet.Reader.ReadUInt16());
                    sbs.AppendLine("Format", packet.Reader.ReadByte());

                    var valc = packet.Reader.ReadUInt32();

                    sbs.AppendLine().AppendLine("Fields Size", valc);

                    /*for (var v = 0U; v < valc; ++v)
                    {
                        byte val = packet.Reader.ReadByte();
                        sbs.AppendFormat("    Field #{0}:    {1}    0x{2:X2}    {3}    {4}{5}",
                                         v.ToString(CultureInfo.InvariantCulture).PadLeft(3, '0'),
                                         val.ToString(CultureInfo.InvariantCulture).PadLeft(3, '0'), val,
                                         Convert.ToString(val, 2).PadLeft(8, '0'),
                                         val > 32 ? Convert.ToChar(val).ToString(CultureInfo.InvariantCulture) : "",
                                         Environment.NewLine);
                    }

                    //ReadFields(packet.Reader, sbs);*/

                    if (true)
                    {
                        var c1 = ReadLengthedDataFromStream(packet.Reader, 5);
                        var c2 = ReadLengthedDataFromStream(packet.Reader, 5);

                        sbs.AppendLine().AppendLine(String.Format("    Counter1: {0} | Counter2: {1}", c1, c2)).AppendLine();

                        for (var r = 0UL; r < c2; ++r)
                        {
                            var fieldId = ReadLengthedDataFromStream2(packet.Reader, 5);
                            var type = ReadLengthedDataFromStream(packet.Reader, 5);
                            var data = "";

                            switch (type)
                            {
                                case 1:
                                case 5:
                                case 14:
                                case 15:
                                case 16:
                                case 19:
                                    data = ReadLengthedDataFromStream(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);
                                    break;

                                case 4:
                                    data = String.Format("Float: {0}", packet.Reader.ReadSingle());
                                    break;

                                case 2:
                                case 21:
                                    data = ReadLengthedDataFromStream2(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);
                                    break;

                                case 18:
                                    data = String.Format("X: {0} | Y: {1} | Z: {2}", packet.Reader.ReadSingle(), packet.Reader.ReadSingle(), packet.Reader.ReadSingle());
                                    break;

                                case 6:
                                    data = Encoding.UTF8.GetString(packet.Reader.ReadBytes((Int32)ReadLengthedDataFromStream(packet.Reader, 5)));
                                    break;

                                case 7:
                                    {
                                        var ltype = ReadLengthedDataFromStream(packet.Reader, 5);
                                        /*var lc1 = */ReadLengthedDataFromStream(packet.Reader, 5);
                                        var lc2 = ReadLengthedDataFromStream(packet.Reader, 5);

                                        HeroTypes tE;
                                        Enum.TryParse(ltype.ToString(CultureInfo.InvariantCulture), out tE);

                                        var ssbs = new StringBuilder(String.Format("{2}    List of {0} | Count: {1}", tE, lc2, Environment.NewLine)).AppendLine();

                                        for (var j = 0UL; j < lc2; ++j)
                                        {
                                            var ind = ReadLengthedDataFromStream(packet.Reader, 5);
                                            var ldata = ReadLengthedDataFromStream(packet.Reader, 5);

                                            ssbs.AppendLine(String.Format("        Ind: {0} | Data: {1}", ind, ldata));
                                        }

                                        data = ssbs.ToString();
                                    }
                                    break;

                                case 8:
                                    {
                                        var lType = ReadLengthedDataFromStream(packet.Reader, 5);
                                        var lValT = ReadLengthedDataFromStream(packet.Reader, 5);

                                        /*var lc1 = */ReadLengthedDataFromStream(packet.Reader, 5);
                                        var lc2 = ReadLengthedDataFromStream(packet.Reader, 5);

                                        HeroTypes lE, lV;
                                        Enum.TryParse(lType.ToString(CultureInfo.InvariantCulture), out lE);
                                        Enum.TryParse(lValT.ToString(CultureInfo.InvariantCulture), out lV);

                                        var ssbs = new StringBuilder(String.Format("{3}    Lookup List of {0} | ValT: {1} | Count: {2}", lE, lV, lc2, Environment.NewLine)).AppendLine();
                                        for (var j = 0UL; j < lc2; ++j)
                                        {
                                            if (lType != 0)
                                            {
                                                var ind = ReadLengthedDataFromStream(packet.Reader, 5);
                                                var ldata = ReadLengthedDataFromStream(packet.Reader, 5);

                                                ssbs.AppendLine(String.Format("        Ind: {0} | Data: {1}", ind, ldata));
                                            }
                                            else
                                            {
                                                /*var st = */packet.Reader.ReadByte(); // 210 0xD2
                                                var str1 = Encoding.UTF8.GetString(packet.Reader.ReadBytes((Int32) ReadLengthedDataFromStream(packet.Reader, 5)));
                                                var bdata = ReadLengthedDataFromStream(packet.Reader, 5);
                                                ssbs.AppendLine(String.Format("        Str1: {0} | Str2: {1}", str1, bdata));
                                            }
                                        }
                                        data = ssbs.ToString();
                                    }
                                    break;

                                case 3:
                                    data = packet.Reader.ReadByte() == 1 ? "True" : "False";
                                    break;

                                case 9:
                                    {
                                        /*var lc1 = */ReadLengthedDataFromStream(packet.Reader, 5);
                                        var lc2 = ReadLengthedDataFromStream(packet.Reader, 5);

                                        var ssbs = new StringBuilder(String.Format("{1}    Embedded Class | Count: {0}",  lc2, Environment.NewLine)).AppendLine();

                                        for (var j = 0UL; j < lc2; ++j)
                                        {
                                            var fId = ReadLengthedDataFromStream(packet.Reader, 5);
                                            var ltype = ReadLengthedDataFromStream(packet.Reader, 5);

                                            var adata = "";

                                            if (ltype == 2)
                                                adata = ReadLengthedDataFromStream2(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);

                                            ssbs.AppendLine(String.Format("        F Id: {0} | Type: {1} | Data: {2}", fId, ltype, adata));

                                        }

                                        data = ssbs.ToString();
                                    }
                                    break;
                            }
                            sbs.AppendLine(String.Format("    F Id: {0} | Type: {1} | Data: {2}", fieldId, type, data));
                            //var data = ReadLengthedDataFromStream(packet.Reader, 5);
                        }
                    }
                }

                sb.AppendLine(sbs.ToString().Replace(Environment.NewLine, String.Format("{0}    ", Environment.NewLine)));
            }

            if (true) // Extra Character
            {
                var sbs = new StringBuilder().AppendLine("Extra Character").AppendLine("Character Guid", packet.Reader.ReadUInt64());

                var flags = packet.Reader.ReadByte();
                sbs.AppendLine("Flags", flags);

                if ((flags & 0x80) != 0)
                    sbs.AppendLine("Class Id", packet.Reader.ReadUInt64());

                if ((flags & 0x40) != 0)
                    sbs.AppendLine("Template Id", packet.Reader.ReadUInt64());

                if ((flags & 0x20) != 0)
                {
                    sbs.AppendLine("Parent Node Id1", packet.Reader.ReadUInt64());
                    sbs.AppendLine("Parent Node Id2", packet.Reader.ReadUInt64());
                }

                if ((flags & 0x10) != 0)
                {
                    var unkbyte = packet.Reader.ReadByte();
                    sbs.AppendLine("Unk Byte", unkbyte);

                    if ((unkbyte & 0x1) != 0 || (unkbyte & 0x2) != 0)
                    {
                        var count2 = packet.Reader.ReadUInt32();

                        sbs.AppendLine().AppendLine("Unk Count", count2);

                        for (var j = 0U; j < count2; ++j)
                            sbs.AppendLine(String.Format("    Unk Guid #{0}", j), packet.Reader.ReadUInt64());
                    }
                }

                if ((flags & 0x08) != 0)
                {
                    sbs.AppendLine().AppendLine("Fields:");
                    sbs.AppendLine("Version", packet.Reader.ReadUInt16());
                    sbs.AppendLine("Format", packet.Reader.ReadByte());

                    var valc = packet.Reader.ReadUInt32();

                    sbs.AppendLine().AppendLine("Fields Size", valc);

                    /*for (var v = 0U; v < valc; ++v)
                    {
                        var val = packet.Reader.ReadByte();
                        sbs.AppendFormat("    Field #{0}:    {1}    0x{2:X2}    {3}    {4}{5}",
                                         v.ToString(CultureInfo.InvariantCulture).PadLeft(3, '0'),
                                         val.ToString(CultureInfo.InvariantCulture).PadLeft(3, '0'), val,
                                         Convert.ToString(val, 2).PadLeft(8, '0'),
                                         val > 32 ? Convert.ToChar(val).ToString(CultureInfo.InvariantCulture) : "",
                                         Environment.NewLine);
                    }

                    //ReadFields(packet.Reader, sbs);*/

                    if (true)
                    {
                        var c1 = ReadLengthedDataFromStream(packet.Reader, 5);
                        var c2 = ReadLengthedDataFromStream(packet.Reader, 5);

                        sbs.AppendLine().AppendLine(String.Format("    Counter1: {0} | Counter2: {1}", c1, c2)).AppendLine();

                        for (var r = 0UL; r < c2; ++r)
                        {
                            var fieldId = ReadLengthedDataFromStream2(packet.Reader, 5);
                            var type = ReadLengthedDataFromStream(packet.Reader, 5);
                            var data = "";

                            switch (type)
                            {
                                case 1:
                                case 5:
                                case 14:
                                case 15:
                                case 16:
                                case 19:
                                    data = ReadLengthedDataFromStream(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);
                                    break;

                                case 4:
                                    data = String.Format("Float: {0}", packet.Reader.ReadSingle());
                                    break;

                                case 2:
                                case 21:
                                    data = ReadLengthedDataFromStream2(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);
                                    break;

                                case 18:
                                    data = String.Format("X: {0} | Y: {1} | Z: {2}", packet.Reader.ReadSingle(), packet.Reader.ReadSingle(), packet.Reader.ReadSingle());
                                    break;

                                case 6:
                                    data = Encoding.UTF8.GetString(packet.Reader.ReadBytes((Int32)ReadLengthedDataFromStream(packet.Reader, 5)));
                                    break;

                                case 7:
                                    {
                                        var ltype = ReadLengthedDataFromStream(packet.Reader, 5);
                                        /*var lc1 = */ReadLengthedDataFromStream(packet.Reader, 5);
                                        var lc2 = ReadLengthedDataFromStream(packet.Reader, 5);

                                        HeroTypes tE;
                                        Enum.TryParse(ltype.ToString(CultureInfo.InvariantCulture), out tE);

                                        var ssbs = new StringBuilder(String.Format("{2}    List of {0} | Count: {1}", tE, lc2, Environment.NewLine)).AppendLine();

                                        for (var j = 0UL; j < lc2; ++j)
                                        {
                                            var ind = ReadLengthedDataFromStream(packet.Reader, 5);
                                            var ldata = ReadLengthedDataFromStream(packet.Reader, 5);

                                            ssbs.AppendLine(String.Format("        Ind: {0} | Data: {1}", ind, ldata));
                                        }

                                        data = ssbs.ToString();
                                    }
                                    break;

                                case 8:
                                    {
                                        var lType = ReadLengthedDataFromStream(packet.Reader, 5);
                                        var lValT = ReadLengthedDataFromStream(packet.Reader, 5);

                                        /*var lc1 = */ReadLengthedDataFromStream(packet.Reader, 5);
                                        var lc2 = ReadLengthedDataFromStream(packet.Reader, 5);

                                        HeroTypes lE, lV;
                                        Enum.TryParse(lType.ToString(CultureInfo.InvariantCulture), out lE);
                                        Enum.TryParse(lValT.ToString(CultureInfo.InvariantCulture), out lV);

                                        var ssbs = new StringBuilder(String.Format("{3}    Lookup List of {0} | ValT: {1} | Count: {2}", lE, lV, lc2, Environment.NewLine)).AppendLine();
                                        for (var j = 0UL; j < lc2; ++j)
                                        {
                                            if (lType != 0)
                                            {
                                                var ind = ReadLengthedDataFromStream(packet.Reader, 5);
                                                var ldata = ReadLengthedDataFromStream(packet.Reader, 5);

                                                ssbs.AppendLine(String.Format("        Ind: {0} | Data: {1}", ind, ldata));
                                            }
                                            else
                                            {
                                                /*var st = */packet.Reader.ReadByte(); // 210 0xD2
                                                var str1 = Encoding.UTF8.GetString(packet.Reader.ReadBytes((Int32) ReadLengthedDataFromStream(packet.Reader, 5)));
                                                String bdata;
                                                if (lValT == 9)
                                                {
                                                    /*var lc11 = */ReadLengthedDataFromStream(packet.Reader, 5);
                                                    var lc21 = ReadLengthedDataFromStream(packet.Reader, 5);

                                                    var sssbs = new StringBuilder(String.Format("{1}    Embedded Class | Count: {0}", lc21, Environment.NewLine)).AppendLine();

                                                    for (var k = 0UL; k < lc21; ++k)
                                                    {
                                                        var fId = ReadLengthedDataFromStream2(packet.Reader, 5);
                                                        var ltype = ReadLengthedDataFromStream(packet.Reader, 5);

                                                        var adata = "";

                                                        if (ltype == 1  || ltype == 5)
                                                            adata = ReadLengthedDataFromStream(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);

                                                        if (ltype == 2)
                                                            adata = ReadLengthedDataFromStream2(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);

                                                        if (ltype == 6)
                                                            adata = Encoding.UTF8.GetString(packet.Reader.ReadBytes((Int32) ReadLengthedDataFromStream(packet.Reader, 5)));

                                                        sssbs.AppendLine(String.Format("        F Id: {0} | Type: {1} | Data: {2}", fId, ltype, adata));

                                                    }

                                                    bdata = sssbs.ToString();
                                                }
                                                else
                                                    bdata = ReadLengthedDataFromStream(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);

                                                ssbs.AppendLine(String.Format("        Str1: {0} | Str2: {1}", str1, bdata));
                                            }
                                        }
                                        data = ssbs.ToString();
                                    }
                                    break;

                                case 3:
                                    data = packet.Reader.ReadByte() == 1 ? "True" : "False";
                                    break;

                                case 9:
                                    {
                                        /*var lc1 = */ReadLengthedDataFromStream(packet.Reader, 5);
                                        var lc2 = ReadLengthedDataFromStream(packet.Reader, 5);

                                        var ssbs = new StringBuilder(String.Format("{1}    Embedded Class | Count: {0}",  lc2, Environment.NewLine)).AppendLine();

                                        for (var j = 0UL; j < lc2; ++j)
                                        {
                                            var fId = ReadLengthedDataFromStream(packet.Reader, 5);
                                            var ltype = ReadLengthedDataFromStream(packet.Reader, 5);

                                            var adata = "";

                                            if (ltype == 2)
                                                adata = ReadLengthedDataFromStream2(packet.Reader, 5).ToString(CultureInfo.InvariantCulture);

                                            ssbs.AppendLine(String.Format("        F Id: {0} | Type: {1} | Data: {2}", fId, ltype, adata));

                                        }

                                        data = ssbs.ToString();
                                    }
                                    break;
                            }
                            sbs.AppendLine(String.Format("    F Id: {0} | Type: {1} | Data: {2}", fieldId, type, data));
                            //var data = ReadLengthedDataFromStream(packet.Reader, 5);
                        }
                    }
                }

                sb.AppendLine(sbs.ToString().Replace(Environment.NewLine, String.Format("{0}    ", Environment.NewLine)));
            }

            return sb.AppendLine("Unk Short1", packet.Reader.ReadUInt16()).AppendLine("Unk Short2", packet.Reader.ReadUInt16())
                .AppendLine("XML", packet.Reader.ReadString(true)).AppendLine("Unk Long", packet.Reader.ReadUInt64());
        }

        [Parser(Opcode.ClientReplicationTransaction)]
        public static StringBuilder HandleClientReplicationTransaction(Packet packet)
        {
            var sb = new StringBuilder().AppendLine("Unk Int", packet.Reader.ReadUInt32());

            var reader = ReadFrame(packet.Reader, sb);

            if (reader.CanRead(1))
            {
                var sc = ReadLengthedDataFromStream(reader, 5);
                for (var i = 0UL; i < sc; ++i)
                {
                    var sid = ReadLengthedDataFromStream(reader, 5);
                    var baseClassId = ReadLengthedDataFromStream(reader, 5);

                    var gCCount = ReadLengthedDataFromStream(reader, 5);
                    for (var j = 0UL; j < gCCount; ++j)
                    {
                        var gCId = ReadLengthedDataFromStream(reader, 5);
                    }

                    var fieldC = ReadLengthedDataFromStream(reader, 5);

                    for (var j = 0UL; j < fieldC; ++j)
                    {
                        var fID = ReadLengthedDataFromStream(reader, 5);
                        var typeC = ReadLengthedDataFromStream(reader, 5);

                        for (var k = 0UL; k < typeC; ++k)
                        {
                            var type = ReadLengthedDataFromStream(reader, 5);
                            var cId = ReadLengthedDataFromStream(reader, 5);
                            var sId = ReadLengthedDataFromStream(reader, 5);
                        }
                    }
                }
                sb.AppendLine("");
            }

            ReadUnkValues(packet.Reader, sb, 5);

            return sb;
        }

        [Parser(Opcode.SetCharacterRendezvousPoint)]
        public static StringBuilder HandleSetCharacterRendezvousPoint(Packet packet)
        {
            var sb = new StringBuilder().AppendLine("UnkLong", packet.Reader.ReadUInt64()).AppendLine("UnkInt", packet.Reader.ReadUInt32());

            for (var i = 0; i < 6; ++i)
                sb.AppendLine("UnkFloat", packet.Reader.ReadSingle());

            return sb.AppendLine("UnkByte", packet.Reader.ReadByte());
        }

        public static UInt64 ReadLengthedDataFromStream(EndianBinaryReader reader, Byte type)
        {
            if (type <= 1)
            {
                if (reader.CanRead(1))
                {
                    byte a = reader.ReadByte();
                    if (a <= 127)
                        return a;

                    if ((Byte) (a + 80) <= 15)
                        return GetLong(reader.ReadBytes(a - 175));
                }
                return 0;
            }

            if (!reader.CanRead(1))
                return 0;

            byte b = reader.ReadByte();

            if (b <= 191)
                return b;

            return (Byte) (b + 56) > 7 ? 0 : GetLong(reader.ReadBytes(b - 199));
        }

        public static UInt64 GetLong(Byte[] buffer)
        {
            var temp = new Byte[8];
            Array.Copy(buffer, 0, temp, 0, buffer.Length);
            return BitConverter.ToUInt64(temp, 0);
        }

        public static void ReadUnkValues(EndianBinaryReader reader, StringBuilder sb, Byte type)
        {
            var rflags = reader.ReadByte();
            sb.AppendLine("Flags", rflags);
            //
            if ((rflags & 1) != 0)
            {
                var ccount = ReadLengthedDataFromStream(reader, 5);
                sb.AppendLine("Char count", ccount);

                for (var i = 0UL; i < ccount; ++i)
                {
                    sb.AppendLine().AppendFormat("Character #{0}{1}", i + 1, Environment.NewLine).AppendLine("    Node Id", ReadLengthedDataFromStream(reader, type));

                    var flags = reader.ReadByte();
                    sb.AppendLine("    Flags", flags);

                    if ((flags & 0x80) != 0)
                        sb.AppendLine("    Class Id", ReadLengthedDataFromStream(reader, type));

                    if ((flags & 0x40) != 0)
                        sb.AppendLine("    Template Id", ReadLengthedDataFromStream(reader, type));

                    if ((flags & 0x20) != 0)
                        sb.AppendLine("    Parent Node Id", ReadLengthedDataFromStream(reader, type));

                    if ((flags & 0x10) != 0)
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

                    if ((flags & 0x08) == 0)
                        continue;

                    var sbs = new StringBuilder();

                    ReadFields(reader, sbs, type);

                    sb.Append(sbs.ToString().Replace(Environment.NewLine, String.Format("    {0}", Environment.NewLine)));
                }
            }

            if ((rflags & 2) == 0)
                return;

            if (type <= 1)
            {
                var cou = 0UL;
                var by = reader.ReadByte();
                if (by == 135)
                    cou = ReadLengthedDataFromStream(reader, type);

                for (var i = 0UL; i < cou; ++i)
                    sb.AppendLine(String.Format("Unk Val #{0}", i), ReadLengthedDataFromStream(reader, type));
            }
            else
            {
                var cou = ReadLengthedDataFromStream(reader, type);
                sb.AppendLine().AppendLine("Val count", cou);

                for (var i = 0UL; i < cou; ++i)
                    sb.AppendLine(String.Format("Unk Val #{0}", i), ReadLengthedDataFromStream(reader, type));
            }
        }

        public static void ReadFields(EndianBinaryReader reader, StringBuilder sb, Byte type)
        {
            var version = ReadLengthedDataFromStream(reader, type);
            if (version == 0)
                return;

            sb.AppendLine("Fields version", version);

            var format = ReadLengthedDataFromStream(reader, type);
            if (format == 0)
                return;

            Byte[] data;

            sb.AppendLine("Format", format);

            if (version >= 4)
            {
                if (!ReadPayload(reader, type, out data))
                    return;

                sb.AppendLine("Data", BitConverter.ToString(data).Replace("-", " "));
                return;
            }

            var count = ReadLengthedDataFromStream(reader, type);
            if (count == 0)
                return;

            sb.AppendLine().AppendLine("Count", count);

            for (UInt64 i = 0; i < count; ++i)
            {
                sb.AppendLine().AppendLine(String.Format("    Field #{0}", i + 1));

                var id = ReadLengthedDataFromStream(reader, type);
                if (id == 0)
                    return;

                sb.AppendLine("        Id", id);

                var size = ReadLengthedDataFromStream(reader, type);
                if (size == 0)
                    return;

                sb.AppendLine("        Size", size);

                ReadPayload(reader, type, out data);
            }
        }

        public static void ReadFields(EndianBinaryReader reader, StringBuilder sb)
        {
            /*var count = reader.ReadUInt32();
            const byte type = 5;

            var pList = new Dictionary<UInt64, Object>();

            for (UInt64 i = 0; i < count; )
            {
                var id = ReadLengthedDataFromStream(reader, type);

                switch (id)
                {
                    case  1: // 
                    case  5: //
                    case 14: // Unk
                    case 15: // 
                    case 16: // 
                    case 19: // 
                    case 20: // 
                        //pList.Add(id, ReadLengthedDataFromStream(reader, type));
                        break;

                    case 2:
                    case 21:
                        //pList.Add(id, ReadLengthedDataFromStream2(reader, type));
                        break;

                    case 3:
                        //pList.Add(id, reader.ReadByte() == 1);
                        break;

                    case 4:
                        //pList.Add(id, reader.ReadSingle());
                        //i += 3;
                        break;

                    case 6: // String
                        //pList.Add(id, Encoding.UTF8.GetString(reader.ReadBytes((Int32) ReadLengthedDataFromStream(reader, type))));
                        break;

                    case 7: // List
                        break;

                    case 8: // Lookup List
                        break;

                    case 9: // Class unk
                        break;

                    case 10: // Unk, unserializeable
                        break;

                    case 17: // Timer
                        var a = ReadLengthedDataFromStream(reader, type);
                        var b = ReadLengthedDataFromStream2(reader, type);
                        var c = ReadUnkBool(reader, type);
                        var d = ReadLengthedDataFromStream2(reader, type);
                        var e = ReadLengthedDataFromStream2(reader, type);
                        var f = ReadLengthedDataFromStream2(reader, type);
                        var g = ReadLengthedDataFromStream2(reader, type);
                        var h = ReadLengthedDataFromStream2(reader, type);
                        var ii = ReadLengthedDataFromStream2(reader, type);
                        var j = ReadLengthedDataFromStream(reader, type);
                        var k = ReadLengthedDataFromStream2(reader, type);
                        var l = ReadLengthedDataFromStream2(reader, type);
                        break;

                    case 18: // Vector3
                        break;

                    case 22: // Raw Data
                        break;
                }

                var size = ReadLengthedDataFromStream(reader, type);

                pList[i] = new Tuple<UInt64, Object>(id, null);

                for (UInt64 j = 0; j < size; ++j)
                {
                    ((List<Byte>)pList[i]).Add(reader.ReadByte());
                }

                i += 1;
            }*/
        }

        public static Boolean ReadPayload(EndianBinaryReader reader, Byte type, out Byte[] data)
        {
            UInt64 a;
            if (type > 1)
            {
                a = ReadLengthedDataFromStream(reader, type);
                if (a == 0)
                {
                    data = new Byte[0];
                    return true;
                }
            }
            else
            {
                byte b = reader.ReadByte();
                if (b == 133)
                {
                    a = ReadLengthedDataFromStream(reader, type);
                    if (a == 0)
                    {
                        data = new Byte[0];
                        return true;
                    }
                }
                else
                {
                    data = new Byte[0];
                    return false;
                }
            }

            if (reader.CanRead((UInt32) a))
            {
                data = reader.ReadBytes((Int32) a);
                return true;
            }

            data = new Byte[0];
            return false;
        }

        public static EndianBinaryReader ReadFrame(EndianBinaryReader reader, StringBuilder sb)
        {
            var count = reader.ReadUInt32();
            sb.AppendLine("Frame size", count);
            return new EndianBinaryReader(EndianBitConverter.Little, new MemoryStream(reader.ReadBytes((Int32)count)));
        }

        public static UInt64 ReadLengthedDataFromStream2(EndianBinaryReader reader, Byte type)
        {
            if (type <= 1)
            {
                if (reader.CanRead(1))
                {
                    byte b = reader.ReadByte();
                    if (b <= 127)
                        return b;

                    if ((Byte) (b + 96) <= 15)
                        return GetLong(reader.ReadBytes(b - 159));

                    if ((Byte) (b + 112) <= 15)
                        return GetLong(reader.ReadBytes(b - 143));

                    if (b == 143)
                        return 0x8000000000000000;
                }
                return 0;
            }
            
            if (reader.CanRead(1))
            {
                byte b = reader.ReadByte();
                if (b <= 191)
                    return b;

                if ((Byte) (b + 56) <= 7)
                    return GetLong(reader.ReadBytes(b - 199));

                if ((Byte) (b + 64) > 7)
                    return b == 208 ? 0x8000000000000000 : 0;

                return GetLong(reader.ReadBytes(b - 191));
            }
            return 0;
        }

        public static Boolean ReadUnkBool(EndianBinaryReader reader, Byte type)
        {
            if (type > 1)
            {
                if (reader.CanRead(1))
                    return reader.ReadByte() == 1;

                return false;
            }

            if (reader.CanRead(1))
                return reader.ReadByte() == 129;

            return false;
        }
    }
}