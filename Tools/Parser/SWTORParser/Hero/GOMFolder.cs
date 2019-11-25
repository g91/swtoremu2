using System;
using System.Collections.Generic;
using SWTORParser.Hero.Definition;

namespace SWTORParser.Hero
{
    public class GOMFolder : IComparable<GOMFolder>
    {
        public List<GOMFolder> Folders;
        public string Name;
        public HeroNodeDef Node;
        public Dictionary<string, GOMFolder> dictNameToFolder;

        public GOMFolder()
        {
            Folders = new List<GOMFolder>();
            dictNameToFolder = new Dictionary<string, GOMFolder>();
        }

        #region IComparable<GOMFolder> Members

        public int CompareTo(GOMFolder other)
        {
            return string.Compare(Name, other.Name);
        }

        #endregion

        public GOMFolder CreateFolder(string name)
        {
            GOMFolder gomFolder = GetFolder(name);
            if (gomFolder == null)
            {
                gomFolder = new GOMFolder();
                gomFolder.Name = name;
                Folders.Add(gomFolder);
                dictNameToFolder[name] = gomFolder;
            }
            return gomFolder;
        }

        public GOMFolder GetFolder(string name)
        {
            var gomFolder = (GOMFolder) null;
            dictNameToFolder.TryGetValue(name, out gomFolder);
            return gomFolder;
        }

        public void SetNode(HeroNodeDef node)
        {
            Node = node;
        }

        public void Sort()
        {
            foreach (GOMFolder gomFolder in Folders)
                gomFolder.Sort();
            Folders.Sort();
        }

        public override string ToString()
        {
            return Name;
        }
    }
}