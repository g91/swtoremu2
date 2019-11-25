using Hero.Definition;
using Hero.Types;
using System;
using System.Collections.Generic;

namespace Hero
{
  public class VariableList : List<Variable>
  {
    protected int nextId;
    protected Dictionary<ulong, Variable> dictIdToVariable;

    public VariableList()
    {
      this.dictIdToVariable = new Dictionary<ulong, Variable>();
      this.nextId = 0;
    }

    public void ProcessFields(VariableList.ProcessFieldsCallback callback)
    {
      foreach (Variable variable in (List<Variable>) this)
        callback(variable.Field, variable.Value);
    }

    public bool GetVariable<T>(string name, out T value) where T : HeroAnyValue
    {
      value = default (T);
      foreach (Variable variable in (List<Variable>) this)
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
		HeroFieldDef definition = field.Definition as HeroFieldDef;
		if ((definition != null) && (definition.FieldType.Type != value.Type.Type))
		{
			throw new Exception("Type mismatch exception");
		}
		this.dictIdToVariable.TryGetValue(field.Id, out variable);
		if (variable != null)
		{
			variableId = variable.VariableId;
			variable.Value = value;
		}
		else
		{
			variableId = this.GetNextId();
			variable = new Variable(field, variableId, value);
			this.dictIdToVariable[field.Id] = variable;
			base.Add(variable);
		}
    }

    public void SetVariable<T>(string name, T value) where T : HeroAnyValue
    {
      if (!GOM.Instance.DefinitionsByName[HeroDefinition.Types.Field].ContainsKey(name))
        throw new Exception("Field name does not exist");
      this.SetVariable<T>(new DefinitionId((GOM.Instance.DefinitionsByName[HeroDefinition.Types.Field][name] as HeroFieldDef).Id), value);
    }

    public int GetNextId()
    {
      ++this.nextId;
      return this.nextId;
    }

    public delegate void ProcessFieldsCallback(DefinitionId field, HeroAnyValue value);
  }
}
