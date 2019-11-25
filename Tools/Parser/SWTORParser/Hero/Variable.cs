using SWTORParser.Hero.Types;

namespace SWTORParser.Hero
{
    public class Variable
    {
        public DefinitionId Field;
        public HeroAnyValue Value;
        public int VariableId;

        public Variable(DefinitionId field, int variableId, HeroAnyValue value)
        {
            Field = field;
            VariableId = variableId;
            Value = value;
        }

        public override string ToString()
        {
            return string.Format("Field: {0}, varId: {1}, Value: {2}", Field, VariableId, Value);
        }
    }
}