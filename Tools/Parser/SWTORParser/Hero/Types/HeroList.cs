using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SWTORParser.Hero.Types
{
    public class HeroList : HeroAnyValue
    {
        public List<HeroVarId> Data;
        public int NextId;

        public HeroList(HeroType type = null)
        {
            Type = new HeroType(HeroTypes.List) { Values = type };
            NextId = 0;
        }

        public override string ValueText
        {
            get
            {
                return Data == null ? "{ }" : new StringBuilder(Data.Aggregate("{ ", (current, heroVarId) => current + heroVarId.Value.ValueText + ", ")).Append(" }").ToString();
            }
        }

        public int GetNextId()
        {
            return ++NextId;
        }

        public void Add<T>(T value) where T : HeroAnyValue
        {
            if (Data == null)
                Data = new List<HeroVarId>();

            Data.Add(new HeroVarId(GetNextId(), value));
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            Data = new List<HeroVarId>();
            var deserializeList = new DeserializeList(stream, 1);

            if (Type.Values == null)
                Type.SetValuesType(deserializeList.ListType);

            for (var index1 = 0U; index1 < deserializeList.Count; ++index1)
            {
                uint index2;
                bool b;
                int variableId;
                deserializeList.GetFieldIndex(out index2, out b, out variableId);
                var heroAnyValue = Create(Type.Values);
                heroAnyValue.Deserialize(stream);
                Data.Add(new HeroVarId(variableId, heroAnyValue));

                if (variableId > NextId)
                    NextId = variableId;
            }
        }

        public override void Serialize(PackedStream2 stream)
        {
            var count = 0;
            if (Data != null)
                count = Data.Count;

            var serializeList = new SerializeList(stream, 1, Type.Values.Type, count);
            for (var index = 0; index < count; ++index)
            {
                serializeList.SetFieldIndex(index, Data[index].VarId);
                Data[index].Value.Serialize(stream);
            }
        }
    }
}