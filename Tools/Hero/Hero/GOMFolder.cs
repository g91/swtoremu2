using Hero.Definition;
using System;
using System.Collections.Generic;

namespace Hero
{
  public class GOMFolder : IComparable<GOMFolder>
  {
    public string Name;
    public List<GOMFolder> Folders;
    public Dictionary<string, GOMFolder> dictNameToFolder;
    public HeroNodeDef Node;

    public GOMFolder()
    {
      this.Folders = new List<GOMFolder>();
      this.dictNameToFolder = new Dictionary<string, GOMFolder>();
    }

    public GOMFolder CreateFolder(string name)
    {
      GOMFolder gomFolder = this.GetFolder(name);
      if (gomFolder == null)
      {
        gomFolder = new GOMFolder();
        gomFolder.Name = name;
        this.Folders.Add(gomFolder);
        this.dictNameToFolder[name] = gomFolder;
      }
      return gomFolder;
    }

    public GOMFolder GetFolder(string name)
    {
      GOMFolder gomFolder = (GOMFolder) null;
      this.dictNameToFolder.TryGetValue(name, out gomFolder);
      return gomFolder;
    }

    public void SetNode(HeroNodeDef node)
    {
      this.Node = node;
    }

    public void Sort()
    {
      foreach (GOMFolder gomFolder in this.Folders)
        gomFolder.Sort();
      this.Folders.Sort();
    }

    public override string ToString()
    {
      return this.Name;
    }

    public int CompareTo(GOMFolder other)
    {
      return string.Compare(this.Name, other.Name);
    }
  }
}
