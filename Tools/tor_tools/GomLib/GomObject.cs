using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib
{
    public class GomObject : DomType
    {
        internal ulong ClassId { get; set; }
        public DomClass DomClass { get; internal set; }

        public List<DomClass> GlommedClasses { get; internal set; }

        internal int DataLength { get; set; }
        internal byte[] DataBuffer { get; set; }

        public int Offset20 { get; set; }
        public short NumGlommed { get; set; }
        public short Offset26 { get; set; }
        public int ObjectSizeInFile { get; set; }
        public short Offset2C { get; set; }
        public short Offset2E { get; set; }
        public byte Offset30 { get; set; }
        public byte Offset31 { get; set; }

        /// <summary>Adler32 Checksum</summary>
        public long Checksum { get; set; }

        public int Zeroes { get; private set; }

        public int InstanceType { get; internal set; }
        public int NumFields { get; internal set; }

        private GomObjectData _data;
        public GomObjectData Data { get { if (!IsLoaded) { this.Load(); } return _data; } }

        internal bool IsCompressed { get; set; }
        internal int NodeDataOffset { get; set; }
        private bool IsLoaded { get; set; }
        private bool IsUnloaded { get; set; }

        public int DecompressedLength { get; set; }
        //public byte[] FirstBytes { get; set; }

        public override void Link()
        {
            base.Link();
            DomClass = DataObjectModel.Get<DomClass>(ClassId);
        }

        public override void Print(System.IO.TextWriter writer)
        {
            if (!IsLoaded) Load();

            writer.WriteLine("Instance: {2} {0} // Node: {1}", Name, Id, DomClass);
            if (!String.IsNullOrEmpty(Description))
            {
                writer.WriteLine("\t{0}", Description);
            }

            //writer.WriteLine("Compressed Length: 0x{0:X}", DataLength);
            //writer.WriteLine("Offs 0x14: 0x{0:X}", Offset20);
            //writer.WriteLine("NumGlommed: 0x{0:X}", NumGlommed);
            //writer.WriteLine("Offs 0x22: 0x{0:X}", Offset26);
            //writer.WriteLine("ObjSizeInFile: 0x{0:X}", ObjectSizeInFile);
            //writer.WriteLine("Offs 0x28: 0x{0:X}", Offset2C);
            //writer.WriteLine("Offs 0x2A: 0x{0:X}", Offset2E);
            //writer.WriteLine("Offs 0x2C: 0x{0:X}", Offset30);
            //writer.WriteLine("Offs 0x2D: 0x{0:X}", Offset31);
            //writer.WriteLine("Zeroes: {0}", Zeroes);

            //writer.Write("Data: ");
            //for (var i = 0; i < 0xF; i++)
            //{
            //    writer.Write("{0:X2}", FirstBytes[i]);
            //}
            //writer.WriteLine();

            var dataDict = this.Data as GomObjectData;
            if (dataDict != null)
            {
                foreach (var kvp in dataDict.Dictionary)
                {
                    PrintVal(writer, kvp.Key, kvp.Value, "");
                }
            }
        }

        private static void PrintVal(System.IO.TextWriter writer, string key, object val, string tabs)
        {
            if (val is System.Collections.IList)
            {
                System.Collections.IList valList = val as System.Collections.IList;
                writer.WriteLine("{0}{1}", tabs, key);
                for (var i = 0; i < valList.Count; i++)
                {
                    PrintVal(writer, i.ToString(), valList[i], tabs + "   ");
                }
            }
            else if (val is IDictionary<object, object>)
            {
                var valDict = val as IDictionary<object, object>;
                writer.WriteLine("{0}{1}",tabs,key);
                foreach (var valKvp in valDict)
                {
                    PrintVal(writer, valKvp.Key.ToString(), valKvp.Value, tabs + "   ");
                }
            }
            else if (val is GomObjectData)
            {
                var valDict = (val as GomObjectData).Dictionary;
                writer.WriteLine("{0}{1}", tabs, key);
                foreach (var valKvp in valDict)
                {
                    PrintVal(writer, valKvp.Key.ToString(), valKvp.Value, tabs + "   ");
                }
            }
            else
            {
                writer.WriteLine("{0}{1} = {2}", tabs, key, val);
            }
        }

        public void Load()
        {
            if (IsLoaded) { return; }
            if (IsUnloaded) { throw new InvalidOperationException("Cannot reload object once it's unloaded"); }

            if ((NumGlommed > 0) || (ObjectSizeInFile > 0))
            {
                byte[] buffer;

                if (IsCompressed)
                {
                    int dataLen = 8 * NumGlommed + ObjectSizeInFile;
                    int maxLen = dataLen + 8;
                    buffer = new byte[maxLen];

                    // Decompress DataBuffer
                    using (var ms = new System.IO.MemoryStream(DataBuffer))
                    using (var istream = new ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream(ms, new ICSharpCode.SharpZipLib.Zip.Compression.Inflater(false)))
                    {
                        int readBytes = istream.Read(buffer, 0, maxLen);
                        Zeroes = readBytes - dataLen;
                        //istream.Read(buffer, 0, 0xF);
                    }
                }
                else
                {
                    string path = String.Format("/resources/systemgenerated/prototypes/{0}.node", this.Id);
                    TorLib.File protoFile = TorLib.Assets.FindFile(path);
                    using (var fs = protoFile.Open())
                    using (var br = new GomBinaryReader(fs, Encoding.UTF8))
                    {
                        br.ReadBytes(NodeDataOffset);
                        buffer = br.ReadBytes(ObjectSizeInFile);
                        Zeroes = 0;
                    }
                }

                // Load data from decompressed buffer
                using (var ms = new System.IO.MemoryStream(buffer))
                using (var br = new GomBinaryReader(ms))
                {
                    ms.Position = Zeroes;
                    this.GlommedClasses = new List<DomClass>();
                    for (var glomIdx = 0; glomIdx < NumGlommed; glomIdx++)
                    {
                        var glomClassId = br.ReadUInt64();
                        var glomClass = DataObjectModel.Get<DomClass>(glomClassId);
                        this.GlommedClasses.Add(glomClass);
                    }

                    this._data = ScriptObjectReader.ReadObject(this.DomClass, br);
                }

                //FirstBytes = buffer.Take(0xF).ToArray();
            }

            this.DataBuffer = null; // Since we're loaded, we don't need to hold on to the compressed data anymore
            IsLoaded = true;
        }

        public void Unload()
        {
            this._data = null;
            IsLoaded = false;
            IsUnloaded = true;
        }
    }
}
