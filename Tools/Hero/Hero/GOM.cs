using Hero.Definition;
using Hero.Types;
using System;
using System.Collections.Generic;
using System.IO;

namespace Hero
{
  public class GOM
  {
    protected static GOM instance;
    protected Dictionary<ulong, HeroDefinition> definitions;
    public Dictionary<HeroDefinition.Types, Dictionary<string, HeroDefinition>> DefinitionsByName;
    protected Dictionary<IDSpaces, IDSpace> spaces;
    protected GOMFolder root;

    public static GOM Instance
    {
      get
      {
        if (GOM.instance == null)
          GOM.instance = new GOM();
        return GOM.instance;
      }
    }

    public Dictionary<ulong, HeroDefinition> Definitions
    {
      get
      {
        return this.definitions;
      }
    }

    static GOM()
    {
    }

    protected GOM()
    {
      this.definitions = new Dictionary<ulong, HeroDefinition>();
      this.DefinitionsByName = new Dictionary<HeroDefinition.Types, Dictionary<string, HeroDefinition>>();
      this.DefinitionsByName[HeroDefinition.Types.Association] = new Dictionary<string, HeroDefinition>();
      this.DefinitionsByName[HeroDefinition.Types.Class] = new Dictionary<string, HeroDefinition>();
      this.DefinitionsByName[HeroDefinition.Types.Enumeration] = new Dictionary<string, HeroDefinition>();
      this.DefinitionsByName[HeroDefinition.Types.Field] = new Dictionary<string, HeroDefinition>();
      this.DefinitionsByName[HeroDefinition.Types.Node] = new Dictionary<string, HeroDefinition>();
      this.DefinitionsByName[HeroDefinition.Types.Script] = new Dictionary<string, HeroDefinition>();
      this.spaces = new Dictionary<IDSpaces, IDSpace>();
      this.spaces[IDSpaces.ServerTemporaryNode] = new IDSpace(2000000000UL, 4000000000UL);
      this.root = new GOMFolder();
    }

    public void Initialize()
    {
      this.Parse(Repository.Instance.GetFile("/resources/systemgenerated/client.gom"));
      for (int index = 0; index < 500; ++index)
        this.LoadBucket(index);
      this.root.Sort();
    }

    public void SortRoot()
    {
      this.root.Sort();
    }

    public void Parse(Stream stream)
    {
      while (stream.Position < stream.Length)
      {
        byte[] buffer = new byte[8];
        stream.Read(buffer, 0, buffer.Length);
        uint num1 = BitConverter.ToUInt32(buffer, 0);
        uint num2 = BitConverter.ToUInt32(buffer, 4);
        if ((int) num1 == 1112293956 && (int) num2 == 1)
        {
          this.ParseDBLB(stream, 1);
        }
        else
        {
          if ((int) num1 != 1112293956 || (int) num2 != 2)
            throw new InvalidDataException(string.Format("Unsupported chunk (ID={0:X}, Version={1}", (object) num1, (object) num2));
          this.ParseDBLB(stream, 2);
        }
      }
    }

    public void LoadBucket(int index)
    {
      this.LoadBucket(Repository.Instance.GetFile(string.Format("/resources/systemgenerated/buckets/{0}.bkt", (object) index)));
    }

    public void LoadBucket(Stream stream)
    {
      OmegaStream omegaStream = new OmegaStream(stream);
      omegaStream.CheckResourceHeader(1263878736U, (ushort) 2, (ushort) 2);
      for (int index = 0; index < 2; ++index)
      {
        uint length = omegaStream.ReadUInt();
        this.Parse((Stream) new MemoryStream(omegaStream.ReadBytes(length)));
      }
    }

    public void ParseDBLB(Stream stream, int version)
    {
      byte[] buffer = new byte[4];
      while (stream.Length - stream.Position >= 4L)
      {
        stream.Read(buffer, 0, buffer.Length);
        int length = BitConverter.ToInt32(buffer, 0);
        if (length == 0)
          return;
        if (stream.Length - stream.Position < (long) (length - 4))
          throw new InvalidDataException("Cannot read block, input file truncated");
        byte[] numArray = new byte[length];
        Array.Copy((Array) buffer, 0, (Array) numArray, 0, buffer.Length);
        stream.Read(numArray, 4, length - 4);
        this.ParseDefinition(numArray, version);
        int num = (int) (stream.Position + 7L) & -8;
        stream.Seek((long) num, SeekOrigin.Begin);
      }
      throw new InvalidDataException("Cannot read length, input file truncated");
    }

    public void LoadPrototypes(Stream stream)
    {
      PackedStream_2 packedStream2 = new PackedStream_2(1, stream);
      packedStream2.CheckResourceHeader(1179535696U, (ushort) 1, (ushort) 1);
      ulong num1;
      packedStream2.Read(out num1);
      for (ulong index = 0UL; index < num1; ++index)
      {
        ulong id;
        packedStream2.Read(out id);
        ulong num2;
        packedStream2.Read(out num2);
        this.LoadPrototype(id);
      }
      packedStream2.CheckEnd();
    }

    public void LoadPrototype(ulong id)
    {
      Stream file = Repository.Instance.GetFile(string.Format("/resources/systemgenerated/prototypes/{0}.node", (object) id));
      if (file == null)
        return;
      HeroNodeDef node = new HeroNodeDef(new OmegaStream(file));
      this.definitions[node.Id] = (HeroDefinition) node;
      this.DefinitionsByName[node.Type][node.Name] = (HeroDefinition) node;
      this.AddNode(node);
    }

    protected void AddNode(HeroNodeDef node)
    {
      string[] strArray = node.Name.Split(new char[1]
      {
        '.'
      });
      if (strArray.Length <= 0)
        return;
      GOMFolder gomFolder = this.root;
      foreach (string name in strArray)
        gomFolder = gomFolder.CreateFolder(name);
      gomFolder.SetNode(node);
    }

    public void ParseDefinition(byte[] data, int version)
    {
      HeroDefinition heroDefinition = HeroDefinition.Create(data, version);
      if (heroDefinition == null)
        return;
      this.definitions[heroDefinition.Id] = heroDefinition;
      this.DefinitionsByName[heroDefinition.Type][heroDefinition.Name] = heroDefinition;
      if (heroDefinition.Type != HeroDefinition.Types.Node)
        return;
      this.AddNode(heroDefinition as HeroNodeDef);
    }

    public HeroDefinition LookupDefinitionId(ulong id)
    {
      if (this.definitions.ContainsKey(id))
        return this.definitions[id];
      else
        return (HeroDefinition) null;
    }

    public HeroClass CreateClass(IDSpaces space, string className)
    {
      HeroType classType = this.GetClassType(className);
      if (classType == null)
        return (HeroClass) null;
      ulong num = this.spaces[space].Get();
      HeroClass heroClass = new HeroClass(classType);
      heroClass.ID = num;
      this.spaces[space].Add((HeroAnyValue) heroClass);
      return heroClass;
    }

    public HeroType GetEnumType(string name)
    {
      HeroType heroType = new HeroType(HeroTypes.Enum);
      if (this.DefinitionsByName[HeroDefinition.Types.Enumeration].ContainsKey(name))
      {
        HeroEnumDef heroEnumDef = this.DefinitionsByName[HeroDefinition.Types.Enumeration][name] as HeroEnumDef;
        heroType.Id = new DefinitionId(heroEnumDef.Id);
      }
      return heroType;
    }

    public int GetEnumValue(string enumType, string enumValue)
    {
      int num = 0;
      if (this.DefinitionsByName[HeroDefinition.Types.Enumeration].ContainsKey(enumType))
      {
        HeroEnumDef heroEnumDef = this.DefinitionsByName[HeroDefinition.Types.Enumeration][enumType] as HeroEnumDef;
        for (int index = 0; index < heroEnumDef.Values.Count; ++index)
        {
          if (heroEnumDef.Values[index] == enumValue)
          {
            num = index + 1;
            break;
          }
        }
      }
      return num;
    }

    public HeroType GetClassType(string className)
    {
      if (!this.DefinitionsByName[HeroDefinition.Types.Class].ContainsKey(className))
        return (HeroType) null;
      HeroClassDef heroClassDef = this.DefinitionsByName[HeroDefinition.Types.Class][className] as HeroClassDef;
      return new HeroType(HeroTypes.Class)
      {
        Id = new DefinitionId(heroClassDef.Id)
      };
    }

    public HeroNodeDef GetNode(string nodeName)
    {
      if (this.DefinitionsByName[HeroDefinition.Types.Node].ContainsKey(nodeName))
        return this.DefinitionsByName[HeroDefinition.Types.Node][nodeName] as HeroNodeDef;
      else
        return (HeroNodeDef) null;
    }
  }
}
