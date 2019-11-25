using System;

namespace SWTORParser.Hero.Types
{
    public class HeroVarId : IComparable<string>
    {
        public HeroAnyValue Value;
        public int VarId;
        public int NextId;

        public HeroVarId(int varID, HeroAnyValue value)
        {
            VarId = varID;
            Value = value;
        }

        #region IComparable<string> Members

        public int CompareTo(string other)
        {
            return Value.Type.Type == HeroTypes.String ? (Value as HeroString).Text.CompareTo(other) : 1;
        }

        #endregion

        public static implicit operator HeroAnyValue(HeroVarId x)
        {
            return x.Value;
        }

        public override string ToString()
        {
            return Value != null ? Value.ToString() : "null";
        }
    }
}