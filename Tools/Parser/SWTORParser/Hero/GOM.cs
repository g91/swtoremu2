using System;
using System.Collections.Generic;
using System.IO;
using SWTORParser.Hero.Definition;
using SWTORParser.Hero.Types;

namespace SWTORParser.Hero
{
    public class Gom
    {
        protected static Gom instance;
        public Dictionary<HeroDefinition.Types, Dictionary<string, HeroDefinition>> DefinitionsByName;
        protected GOMFolder Root;
        protected Dictionary<IDSpaces, IDSpace> Spaces;
        protected Dictionary<ulong, HeroDefinition> definitions;

        protected Gom()
        {
            definitions = new Dictionary<ulong, HeroDefinition>();
            DefinitionsByName = new Dictionary<HeroDefinition.Types, Dictionary<string, HeroDefinition>>();
            DefinitionsByName[HeroDefinition.Types.Association] = new Dictionary<string, HeroDefinition>();
            DefinitionsByName[HeroDefinition.Types.Class] = new Dictionary<string, HeroDefinition>();
            DefinitionsByName[HeroDefinition.Types.Enumeration] = new Dictionary<string, HeroDefinition>();
            DefinitionsByName[HeroDefinition.Types.Field] = new Dictionary<string, HeroDefinition>();
            DefinitionsByName[HeroDefinition.Types.Node] = new Dictionary<string, HeroDefinition>();
            DefinitionsByName[HeroDefinition.Types.Script] = new Dictionary<string, HeroDefinition>();
            Spaces = new Dictionary<IDSpaces, IDSpace>();
            Spaces[IDSpaces.ServerTemporaryNode] = new IDSpace(2000000000UL, 4000000000UL);
            Root = new GOMFolder();
        }

        public static Gom Instance
        {
            get
            {
                if (instance == null)
                    instance = new Gom();
                return instance;
            }
        }

        public Dictionary<ulong, HeroDefinition> Definitions
        {
            get { return definitions; }
        }

        public void Initialize()
        {
            Parse(Repository.Instance.GetFile("/resources/systemgenerated/client.gom"));
            for (int index = 0; index < 500; ++index)
                LoadBucket(index);
            Root.Sort();
        }

        public void SortRoot()
        {
            Root.Sort();
        }

        public void Parse(Stream stream)
        {
            while (stream.Position < stream.Length)
            {
                var buffer = new byte[8];
                stream.Read(buffer, 0, buffer.Length);
                uint num1 = BitConverter.ToUInt32(buffer, 0);
                uint num2 = BitConverter.ToUInt32(buffer, 4);
                if ((int) num1 == 1112293956 && (int) num2 == 1)
                {
                    ParseDBLB(stream, 1);
                }
                else
                {
                    if ((int) num1 != 1112293956 || (int) num2 != 2)
                        throw new InvalidDataException(String.Format("Unsupported chunk (ID={0:X}, Version={1}", num1,
                                                                     num2));
                    ParseDBLB(stream, 2);
                }
            }
        }

        public void LoadBucket(int index)
        {
            LoadBucket(Repository.Instance.GetFile(String.Format("/resources/systemgenerated/buckets/{0}.bkt", index)));
        }

        public void LoadBucket(Stream stream)
        {
            var omegaStream = new OmegaStream(stream);
            omegaStream.CheckResourceHeader(1263878736U, 2, 2);
            for (var index = 0; index < 2; ++index)
            {
                var length = omegaStream.ReadUInt();
                Parse(new MemoryStream(omegaStream.ReadBytes(length)));
            }
        }

        public void ParseDBLB(Stream stream, int version)
        {
            var buffer = new byte[4];
            while (stream.Length - stream.Position >= 4L)
            {
                stream.Read(buffer, 0, buffer.Length);
                int length = BitConverter.ToInt32(buffer, 0);
                if (length == 0)
                    return;
                if (stream.Length - stream.Position < (length - 4))
                    throw new InvalidDataException("Cannot read block, input file truncated");
                var numArray = new byte[length];
                Array.Copy(buffer, 0, numArray, 0, buffer.Length);
                stream.Read(numArray, 4, length - 4);
                ParseDefinition(numArray, version);
                int num = (int) (stream.Position + 7L) & -8;
                stream.Seek(num, SeekOrigin.Begin);
            }
            throw new InvalidDataException("Cannot read length, input file truncated");
        }

        public void LoadPrototypes(Stream stream)
        {
            var packedStream2 = new PackedStream2(1, stream);
            packedStream2.CheckResourceHeader(1179535696U, 1, 1);
            ulong num1;
            packedStream2.Read(out num1);
            for (ulong index = 0UL; index < num1; ++index)
            {
                ulong id;
                packedStream2.Read(out id);
                ulong num2;
                packedStream2.Read(out num2);
                LoadPrototype(id);
            }
            packedStream2.CheckEnd();
        }

        public void LoadPrototype(ulong id)
        {
            Stream file =
                Repository.Instance.GetFile(string.Format("/resources/systemgenerated/prototypes/{0}.node", id));
            if (file == null)
                return;
            var node = new HeroNodeDef(new OmegaStream(file));
            definitions[node.Id] = node;
            DefinitionsByName[node.Type][node.Name] = node;
            AddNode(node);
        }

        protected void AddNode(HeroNodeDef node)
        {
            string[] strArray = node.Name.Split(new char[1]
                                                    {
                                                        '.'
                                                    });
            if (strArray.Length <= 0)
                return;
            GOMFolder gomFolder = Root;
            foreach (string name in strArray)
                gomFolder = gomFolder.CreateFolder(name);
            gomFolder.SetNode(node);
        }

        public void ParseDefinition(byte[] data, int version)
        {
            HeroDefinition heroDefinition = HeroDefinition.Create(data, version);
            if (heroDefinition == null)
                return;
            definitions[heroDefinition.Id] = heroDefinition;
            DefinitionsByName[heroDefinition.Type][heroDefinition.Name] = heroDefinition;
            if (heroDefinition.Type != HeroDefinition.Types.Node)
                return;
            AddNode(heroDefinition as HeroNodeDef);
        }

        public HeroDefinition LookupDefinitionId(ulong id)
        {
            if (definitions.ContainsKey(id))
                return definitions[id];
            else
                return null;
        }

        public HeroClass CreateClass(IDSpaces space, string className)
        {
            HeroType classType = GetClassType(className);
            if (classType == null)
                return null;
            ulong num = Spaces[space].Get();
            var heroClass = new HeroClass(classType);
            heroClass.ID = num;
            Spaces[space].Add(heroClass);
            return heroClass;
        }

        public HeroType GetEnumType(string name)
        {
            var heroType = new HeroType(HeroTypes.Enum);
            if (DefinitionsByName[HeroDefinition.Types.Enumeration].ContainsKey(name))
            {
                var heroEnumDef = DefinitionsByName[HeroDefinition.Types.Enumeration][name] as HeroEnumDef;
                heroType.Id = new DefinitionId(heroEnumDef.Id);
            }
            return heroType;
        }

        public int GetEnumValue(string enumType, string enumValue)
        {
            int num = 0;
            if (DefinitionsByName[HeroDefinition.Types.Enumeration].ContainsKey(enumType))
            {
                var heroEnumDef = DefinitionsByName[HeroDefinition.Types.Enumeration][enumType] as HeroEnumDef;
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
            if (!DefinitionsByName[HeroDefinition.Types.Class].ContainsKey(className))
                return null;
            var heroClassDef = DefinitionsByName[HeroDefinition.Types.Class][className] as HeroClassDef;
            return new HeroType(HeroTypes.Class)
                       {
                           Id = new DefinitionId(heroClassDef.Id)
                       };
        }

        public HeroNodeDef GetNode(string nodeName)
        {
            if (DefinitionsByName[HeroDefinition.Types.Node].ContainsKey(nodeName))
                return DefinitionsByName[HeroDefinition.Types.Node][nodeName] as HeroNodeDef;
            else
                return null;
        }
    }
}