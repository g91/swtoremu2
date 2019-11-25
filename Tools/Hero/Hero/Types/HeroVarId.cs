using Hero;
using System;

namespace Hero.Types
{
  public class HeroVarId : IComparable<string>
  {
    public int VarId;
    public HeroAnyValue Value;
    public int nextId;

    public HeroVarId(int varID, HeroAnyValue value)
    {
      this.VarId = varID;
      this.Value = value;
    }

    public static implicit operator HeroAnyValue(HeroVarId x)
    {
      return x.Value;
    }

    public override string ToString()
    {
      if (this.Value != null)
        return this.Value.ToString();
      else
        return "null";
    }

    public int CompareTo(string other)
    {
      if (this.Value.Type.Type == HeroTypes.String)
        return (this.Value as HeroString).Text.CompareTo(other);
      else
        return 1;
    }
  }
}
