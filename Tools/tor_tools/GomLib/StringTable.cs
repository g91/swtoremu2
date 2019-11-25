using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace GomLib
{
    public class StringTable
    {
        private static Dictionary<string, StringTable> fqnMap;
        public static Dictionary<string, string> failedFqns;

        static StringTable()
        {
            fqnMap = new Dictionary<string, StringTable>();
            failedFqns = new Dictionary<string, string>();
        }

        public static StringTable Find(string fqn)
        {
            if (String.IsNullOrEmpty(fqn)) { return null; }

            StringTable result;
            if (failedFqns.ContainsKey(fqn)) { return null; }

            if (fqnMap.TryGetValue(fqn, out result))
            {
                return result;
            }

            result = new StringTable(fqn);
            try
            {
                result.Load();
                fqnMap[fqn] = result;
                return result;
            }
            catch (Exception ex)
            {
                failedFqns.Add(fqn, ex.Message);
                return null;
            }
        }

        private Dictionary<long, StringTableEntry> data;
        public string Fqn { get; private set; }
        public int Version { get; private set; }
        public long Guid { get; private set; }
        public string OwnerFqn { get; private set; }
        public long OwnerId { get; private set; }

        private StringTable(string fqn)
        {
            this.Fqn = fqn;
        }

        public StringTableEntry GetEntry(long id)
        {
            StringTableEntry result;
            if (data.TryGetValue(id, out result))
            {
                return result;
            }

            return null;
        }

        public string GetText(long id, string forFqn)
        {
            StringTableEntry entry;
            if (data.TryGetValue(id, out entry))
            {
                return entry.Text;
            }

            //Console.WriteLine("Cannot find String {0} in StringTable {1} for {2}", id, this.Fqn, forFqn);
            return String.Empty;
        }

        private void Load()
        {
            // Version with String Tables as XML files
            //var path = String.Format("/resources/en-us/{0}.str", this.Fqn.Replace('.','/'));
            //var file = Assets.FindFile(path);
            //if (file == null) { throw new Exception("File not found"); }

            //using (var fs = file.Open())
            //{
            //    var xmlReader = XmlReader.Create(fs);
            //    var xdoc = XDocument.Load(xmlReader);
            //    var xroot = xdoc.Root;

            //    this.Version = xroot.Attribute("version").AsInt();
            //    this.OwnerFqn = (string)xroot.Attribute("owner");
            //    this.OwnerId = xroot.Attribute("ownerID").AsLong();
            //    this.Guid = xroot.Attribute("GUID").AsLong();
            //    this.Fqn = (string)xroot.Attribute("fqn");
            //    var results = from row in xdoc.Descendants("string") select LoadString(row);
            //    data = results.ToDictionary(k => k.Id, v => v);
            //}

            // Version with String Tables as nodes
            //var enUsPath = "en-us." + this.Fqn;
            //var file = DataObjectModel.GetObject(enUsPath);
            //if (file == null) { throw new Exception("StringTable not found"); }

            //var strings = file.Data.strTableVariantStrings as IDictionary<object, object>; // Map<enum, Map<int, string>>
            //var entries = (IDictionary<object,object>)strings.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "MaleMale").Value;
            //data = new Dictionary<long, StringTableEntry>();
            //foreach (var kvp in entries)
            //{
            //    var entry = new StringTableEntry()
            //    {
            //        Id = (long)kvp.Key,
            //        Text = (string)kvp.Value
            //    };
            //    data[entry.Id] = entry;
            //}

            // Version with String Tables as unique file format contained in swtor_en-us_global_1.tor
            var path = String.Format("/resources/en-us/{0}.stb", this.Fqn.Replace('.', '/'));
            var file = TorLib.Assets.FindFile(path);
            if (file == null) { throw new Exception("File not found"); }

            data = new Dictionary<long, StringTableEntry>();

            using (var fs = file.OpenCopyInMemory())
            {
                var br = new GomBinaryReader(fs);
                br.ReadBytes(3);
                int numStrings = br.ReadInt32();

                long streamPos = 0;

                for (var i = 0; i < numStrings; i++)
                {
                    var entryId = br.ReadInt64();
                    var entry_8 = br.ReadInt16();
                    var entry_A = br.ReadSingle();
                    var entryLength = br.ReadInt32();
                    var entryOffset = br.ReadInt32();
                    var entryLength2 = br.ReadInt32();

                    var entry = new StringTableEntry()
                    {
                        Id = entryId,
                        Text = String.Empty
                    };

                    if (entryLength > 0)
                    {
                        streamPos = fs.Position;
                        fs.Position = entryOffset;
                        entry.Text = br.ReadFixedLengthString(entryLength);
                        fs.Position = streamPos;
                    }

                    data[entryId] = entry;
                }
            }
        }

        //private StringTableEntry LoadString(XElement row)
        //{
        //    StringTableEntry result = new StringTableEntry();
        //    result.Id = row.Attribute("id").AsLong();
        //    result.Text = (string)row.Element("text");
        //    result.TextFemale = (string)row.Element("textFemale");
        //    result.InAlien = row.Element("inAlien").AsBool();
        //    result.DisableVoRecording = row.Element("disableVoRecording").AsBool();
        //    return result;
        //}

        public static string TryGetString(string fqn, GomObjectData textRetriever)
        {
            string locBucket = textRetriever.ValueOrDefault<string>("strLocalizedTextRetrieverBucket", null);
            long strId = textRetriever.ValueOrDefault<long>("strLocalizedTextRetrieverStringID", -1);
            string defaultStr = textRetriever.ValueOrDefault<string>("strLocalizedTextRetrieverDesignModeText", String.Empty);

            if ((locBucket == null) || (strId == -1))
            {
                return defaultStr;
            }

            StringTable strTable = null;
            try
            {
                strTable = StringTable.Find(locBucket);
            }
            catch
            {
                strTable = null;
            }

            if (strTable == null)
            {
                return defaultStr;
            }

            string result = strTable.GetText(strId, fqn);
            return result ?? defaultStr;
        }
    }
}
