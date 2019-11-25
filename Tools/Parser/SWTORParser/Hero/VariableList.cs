using System;
using System.Collections.Generic;
using SWTORParser.Hero.Definition;
using SWTORParser.Hero.Types;

namespace SWTORParser.Hero
{
    public class VariableList : List<Variable>
    {
        #region Delegates

        public delegate void ProcessFieldsCallback(DefinitionId field, HeroAnyValue value);

        #endregion

        protected Dictionary<ulong, Variable> dictIdToVariable;
        protected int nextId;

        public VariableList()
        {
            dictIdToVariable = new Dictionary<ulong, Variable>();
            nextId = 0;
        }

        public void ProcessFields(ProcessFieldsCallback callback)
        {
            foreach (Variable variable in this)
                callback(variable.Field, variable.Value);
        }

        public bool GetVariable<T>(string name, out T value) where T : HeroAnyValue
        {
            value = default (T);
            foreach (Variable variable in this)
            {
                if (variable.Field.Definition != null && variable.Field.Definition.Name == name)
                {
                    value = variable.Value as T;
                    return true;
                }
            }
            return false;
        }

        public void SetVariable<T>(DefinitionId field, T value) where T : HeroAnyValue
        {
            int variableId;
            Variable variable;
            var definition = field.Definition as HeroFieldDef;
            if ((definition != null) && (definition.FieldType.Type != value.Type.Type))
            {
                throw new Exception("Type mismatch exception");
            }
            dictIdToVariable.TryGetValue(field.Id, out variable);
            if (variable != null)
            {
                variableId = variable.VariableId;
                variable.Value = value;
            }
            else
            {
                variableId = GetNextId();
                variable = new Variable(field, variableId, value);
                dictIdToVariable[field.Id] = variable;
                base.Add(variable);
            }
        }

        public void SetVariable<T>(string name, T value) where T : HeroAnyValue
        {
            if (!Gom.Instance.DefinitionsByName[HeroDefinition.Types.Field].ContainsKey(name))
                throw new Exception("Field name does not exist");
            SetVariable(
                new DefinitionId((Gom.Instance.DefinitionsByName[HeroDefinition.Types.Field][name] as HeroFieldDef).Id),
                value);
        }

        public int GetNextId()
        {
            ++nextId;
            return nextId;
        }
    }
}