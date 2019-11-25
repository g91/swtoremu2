using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;

namespace SCPTExtractor
{
    public class ScriptCollection : ObservableCollection<HeroScript> { }

    public class HeroScript
    {
        public String Name { get; set; }
        public Int16 SmallVersion { get; set; }
        public Int16 BigVersion { get; set; }
        public List<String> Strings { get; set; }
        public Byte[] ELF { get; set; }
        public String Location { get; set; }

        public HeroScript(String pName, Int16 pSmallVer, Int16 pBigVer)
        {
            Name = pName;
            SmallVersion = pSmallVer;
            BigVersion = pBigVer;
            Strings = new List<string>();
        }

        public override string ToString()
        {
            return this.Name;
        }

        public void AddString(String value)
        {
            Strings.Add(value);
        }

        public void Save(String SavePath)
        {
            File.WriteAllBytes(SavePath + "\\" + Name + ".elf", ELF);
            Location = SavePath + "\\" + Name + ".elf";
        }
    }
}
