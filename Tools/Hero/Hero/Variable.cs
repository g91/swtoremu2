using Hero.Types;

namespace Hero
{
  public class Variable
  {
    public DefinitionId Field;
    public int VariableId;
    public HeroAnyValue Value;

    public Variable(DefinitionId field, int variableId, HeroAnyValue value)
    {
      this.Field = field;
      this.VariableId = variableId;
      this.Value = value;
    }

    public override string ToString()
    {
      return string.Format("Field: {0}, varId: {1}, Value: {2}", (object) this.Field.ToString(), (object) this.VariableId, (object) this.Value.ToString());
    }
  }
}
