using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using TorLib;
using System.Xml;

namespace GomLib
{
    public static class DataObjectModel
    {
        private static Dictionary<int, DomTypeLoaders.IDomTypeLoader> typeLoaderMap = new Dictionary<int, DomTypeLoaders.IDomTypeLoader>();
        private static Dictionary<Type, Dictionary<string, DomType>> nodeLookup = new Dictionary<Type, Dictionary<string, DomType>>();
        private static Dictionary<ulong, DomType> DomTypeMap { get; set; }
        private static DomTypeLoaders.FileInstanceLoader prototypeLoader = new DomTypeLoaders.FileInstanceLoader();
        private static Dictionary<ulong, string> StoredNameMap { get; set; }

        private static List<string> BucketFiles { get; set; }

        private static void AddTypeLoader(DomTypeLoaders.IDomTypeLoader loader)
        {
            var type = loader.SupportedType;
            typeLoaderMap.Add(type, loader);
        }

        static DataObjectModel()
        {
            BucketFiles = new List<string>();
            DomTypeMap = new Dictionary<ulong, DomType>();
            AddTypeLoader(new DomTypeLoaders.EnumLoader());
            AddTypeLoader(new DomTypeLoaders.FieldLoader());
            AddTypeLoader(new DomTypeLoaders.AssociationLoader());
            AddTypeLoader(new DomTypeLoaders.ClassLoader());
            AddTypeLoader(new DomTypeLoaders.InstanceLoader());

            StoredNameMap = new Dictionary<ulong, string>();
            LoadTypeNames();
        }

        public static string GetStoredTypeName(ulong id)
        {
            string result;
            if (StoredNameMap.TryGetValue(id, out result))
            {
                return result;
            }

            return null;
        }

        private static void LoadTypeNames()
        {
            var inFilePath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "gom_type_names.xml");
            using (var fs = System.IO.File.OpenRead(inFilePath))
            {
                var doc = new XmlDocument();
                doc.Load(fs);
                var nav = doc.DocumentElement.CreateNavigator();
                foreach (System.Xml.XPath.XPathNavigator node in nav.Select("//gom_type"))
                {
                    node.MoveToAttribute("id", "");
                    ulong id = ulong.Parse(node.Value);
                    node.MoveToParent();
                    node.MoveToAttribute("name", "");
                    string name = node.Value;
                    StoredNameMap[id] = name;
                }
            }
        }

        public static void OutputTypeNames()
        {
            // Create XML mapping GomType IDs to names
            var outFilePath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "gom_type_names.xml");
            using (XmlTextWriter writer = new XmlTextWriter(outFilePath, Encoding.UTF8))
            {
                writer.WriteStartDocument();
                writer.WriteStartElement("gom_types");

                foreach (var nodeTypeMap in nodeLookup)
                {
                    Type domType = nodeTypeMap.Key;
                    if (domType == typeof(GomObject)) { continue; }

                    foreach (var kvp in nodeTypeMap.Value)
                    {
                        DomType t = kvp.Value;
                        string name = kvp.Key;

                        writer.WriteStartElement("gom_type");
                        writer.WriteAttributeString("id", t.Id.ToString());
                        writer.WriteAttributeString("name", name);
                        writer.WriteEndElement();
                    }
                }

                writer.WriteEndElement();
                writer.WriteEndDocument();
            }
        }

        public static void Load()
        {
            LoadClientGom();
            LoadBuckets();
            LoadPrototypes();
            //Console.WriteLine("Warning: loading of individual (non-bucketed) prototype files is currently disabled");

            foreach (DomType t in DomTypeMap.Values)
            {
                t.Link();
            }
        }

        private static void LoadClientGom()
        {
            File gomFile = Assets.FindFile("/resources/systemgenerated/client.gom");
            using (var fs = gomFile.Open())
            using (var br = new GomBinaryReader(fs, Encoding.UTF8))
            {
                // Check DBLB
                int magicNum = br.ReadInt32();
                if (magicNum != 0x424C4244)
                {
                    throw new InvalidOperationException("client.gom does not begin with DBLB");
                }

                br.ReadInt32(); // Skip 4 bytes

                ReadAllItems(br, 8);
            }
        }

        private static void LoadBuckets()
        {
            LoadBucketList();
            LoadBucketFiles();
        }

        private static void LoadPrototypes()
        {
            File prototypeList = Assets.FindFile("/resources/systemgenerated/prototypes.info");
            using (var fs = prototypeList.Open())
            using (var br = new GomBinaryReader(fs, Encoding.UTF8))
            {
                // Check PINF
                int magicNum = br.ReadInt32();
                if (magicNum != 0x464E4950)
                {
                    throw new InvalidOperationException("prototypes.info does not begin with PINF");
                }

                br.ReadInt32(); // Skip 4 bytes

                int numPrototypes = (int)br.ReadNumber();
                int protoLoaded = 0;
                for (var i = 0; i < numPrototypes; i++)
                {
                    ulong protId = br.ReadNumber();
                    byte flag = br.ReadByte();

                    if (flag == 1)
                    {
                        LoadPrototype(protId);
                        protoLoaded++;
                    }
                }

                Console.WriteLine("Loaded {0} prototype files", protoLoaded);
            }
        }

        private static void LoadPrototype(ulong id)
        {
            string path = String.Format("/resources/systemgenerated/prototypes/{0}.node", id);
            File protoFile = Assets.FindFile(path);
            if (protoFile == null)
            {
                Console.WriteLine("Unable to find {0}", path);
            }

            using (var fs = protoFile.Open())
            using (var br = new GomBinaryReader(fs, Encoding.UTF8))
            {
                // Check PROT
                int magicNum = br.ReadInt32();
                if (magicNum != 0x544F5250)
                {
                    throw new InvalidOperationException(String.Format("{0} does not begin with PROT", path));
                }

                br.ReadInt32(); // Skip 4 bytes

                var proto = (GomObject)prototypeLoader.Load(br);
                proto.Checksum = (long)protoFile.FileInfo.Checksum;
                DomTypeMap.Add(proto.Id, proto);
                AddToNameLookup(proto);
            }
        }

        private static void LoadBucketList()
        {
            File gomFile = Assets.FindFile("/resources/systemgenerated/buckets.info");
            using (var fs = gomFile.Open())
            using (var br = new GomBinaryReader(fs, Encoding.UTF8))
            {
                br.ReadBytes(8); // Skip 8 header bytes

                var c9 = br.ReadByte();
                if (c9 != 0xC9)
                {
                    throw new InvalidOperationException(String.Format("Unexpected character in buckets.info @ offset 0x8 - expected 0xC9 found {0:X2}", c9));
                }

                short numEntries = br.ReadInt16(Endianness.BigEndian);

                for (var i = 0; i < numEntries; i++)
                {
                    string fileName = br.ReadLengthPrefixString();
                    BucketFiles.Add(fileName);
                }
            }
        }

        private static void LoadBucketFiles()
        {
            //var bucketFileName = BucketFiles[0];
            foreach (var bucketFileName in BucketFiles)
            {
                string path = String.Format("/resources/systemgenerated/buckets/{0}", bucketFileName);
                File bucketFile = Assets.FindFile(path);
                using (var fs = bucketFile.Open())
                using (var br = new GomBinaryReader(fs, Encoding.UTF8))
                {
                    br.ReadBytes(0x24); // Skip 24 header bytes

                    ReadAllItems(br, 0x24);
                }
            }
        }

        private static void ReadAllItems(GomBinaryReader br, long offset)
        {
            while (true)
            {
                // Begin Reading Gom Definitions

                int defLength = br.ReadInt32();

                // Length == 0 means we've read them all!
                if (defLength == 0)
                {
                    break;
                }

                //short defFlags = br.ReadInt16();
                //int defType = (defFlags >> 3) & 0x7;
                byte[] defBuffer = new byte[defLength];
                int defZero = br.ReadInt32(); // 4 blank bytes
                ulong defId = br.ReadUInt64(); // 8-byte type ID
                short defFlags = br.ReadInt16(); // 16-bit flag field
                int defType = (defFlags >> 3) & 0x7;

                //var defData = br.ReadBytes(defLength - 6);
                var defData = br.ReadBytes(defLength - 18);
                Buffer.BlockCopy(defData, 0, defBuffer, 18, defData.Length);

                using (var memStream = new System.IO.MemoryStream(defBuffer))
                using (var defReader = new GomBinaryReader(memStream, Encoding.UTF8))
                {
                    DomTypeLoaders.IDomTypeLoader loader;
                    if (typeLoaderMap.TryGetValue(defType, out loader))
                    {
                        var domType = loader.Load(defReader);
                        domType.Id = defId;
                        DomTypeMap.Add(domType.Id, domType);

                        if (String.IsNullOrEmpty(domType.Name))
                        {
                            string storedTypeName;
                            if (StoredNameMap.TryGetValue(domType.Id, out storedTypeName))
                            {
                                domType.Name = storedTypeName;
                            }
                        }

                        AddToNameLookup(domType);
                    }
                    else
                    {
                        throw new InvalidOperationException(String.Format("No loader for DomType 0x{1:X} as offset 0x{0:X}", offset, defType));
                    }
                }

                // Read the required number of padding bytes
                int padding = ((8 - (defLength & 0x7)) & 0x7);
                if (padding > 0)
                {
                    br.ReadBytes(padding);
                }

                offset = offset + defLength + padding;
            }
        }

        private static void AddToNameLookup(DomType type)
        {
            if (String.IsNullOrEmpty(type.Name)) { return; }

            Dictionary<string, DomType> nameMap;
            Type typeType = type.GetType();
            if (!nodeLookup.TryGetValue(typeType, out nameMap))
            {
                nameMap = new Dictionary<string,DomType>();
                nodeLookup[typeType] = nameMap;
            }

            nameMap.Add(type.Name, type);
        }

        public static T Get<T>(ulong typeId) where T : DomType
        {
            DomType t;
            T result;
            if (!DomTypeMap.TryGetValue(typeId, out t))
            {
                //throw new InvalidOperationException(String.Format("Cannot find DOM type with ID {0}", typeId));
                // Console.WriteLine("Cannot find DOM type with ID 0x{0:X}", typeId);
                return null;
            }

            result = t as T;
            if (result == null)
            {
                //throw new InvalidOperationException(String.Format("Type {0} is not of type {1}", t, typeof(T)));
                Console.WriteLine("Type 0x{0:X} is not of type {1}", t.Id, typeof(T));
            }

            return result;
        }

        public static T Get<T>(string name) where T : DomType
        {
            Type resultType = typeof(T);
            Dictionary<string, DomType> nameMap;
            if (!nodeLookup.TryGetValue(resultType, out nameMap))
            {
                return null;
            }

            DomType t;
            if (!nameMap.TryGetValue(name, out t))
            {
                return null;
            }

            return t as T;
        }

        public static GomObject GetObject(string name)
        {
            GomObject result = Get<GomObject>(name);
            if (result != null) { result.Load(); }
            return result;
        }

        public static GomObject GetObject(ulong id)
        {
            GomObject result = Get<GomObject>(id);
            if (result != null) { result.Load(); }
            return result;
        }

        public static SortedDictionary<string, long> GetAllInstanceNames()
        {
            var results = new SortedDictionary<string, long>();

            Type resultType = typeof(GomObject);
            Dictionary<string, DomType> nameMap;
            if (!nodeLookup.TryGetValue(resultType, out nameMap))
            {
                return results;
            }

            foreach (var kvp in nameMap)
            {
                GomObject val = (GomObject)kvp.Value;
                results.Add(kvp.Key, val.Checksum);
            }

            return results;
        }

        public static List<GomObject> GetObjectsStartingWith(string txt)
        {
            List<GomObject> results = new List<GomObject>();

            Type resultType = typeof(GomObject);
            Dictionary<string, DomType> nameMap;
            if (!nodeLookup.TryGetValue(resultType, out nameMap))
            {
                return results;
            }

            foreach (var kvp in nameMap)
            {
                if (kvp.Key.StartsWith(txt))
                {
                    results.Add((GomObject)kvp.Value);
                }
            }

            return results;
        }

        public static void PrintStats(System.IO.TextWriter outStream)
        {
            outStream.WriteLine("Found {0} DOM Types", DomTypeMap.Count);
            foreach (var kvp in DomTypeMap)
            {
                kvp.Value.Print(outStream);
            }
        }

        public static void PrintStats()
        {
            PrintStats(Console.Out);
        }
    }
}
