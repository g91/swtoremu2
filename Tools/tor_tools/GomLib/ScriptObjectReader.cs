using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib
{
    public static class ScriptObjectReader
    {
        public static GomObjectData ReadObject(DomClass domClass, GomBinaryReader reader)
        {
            GomObjectData result = new GomObjectData();
            IDictionary<string, object> resultDict = result.Dictionary;
            if (domClass != null)
            {
                resultDict["Script_Type"] = domClass;
            }
            else
            {
                resultDict["Script_Type"] = null;
            }

            resultDict["Script_TypeId"] = reader.ReadNumber();

            int numFields = (int)reader.ReadNumber();
            resultDict["Script_NumFields"] = numFields;

            ulong fieldId = 0;
            for (var i = 0; i < numFields; i++)
            {
                fieldId += reader.ReadNumber();
                DomField field = DataObjectModel.Get<DomField>(fieldId);
                GomType fieldType = null;
                if (field == null)
                {
                    // No idea what kind of field this is, so we'll skip it but we still need to read the data..
                    fieldType = GomTypeLoader.Load(reader, false);
                }
                else
                {
                    fieldType = field.GomType;

                    // Confirm the type matches
                    if (!field.ConfirmType(reader))
                    {
                        throw new InvalidOperationException("Unexpected field type for field " + field.Name);
                    }
                }

                // Read in the data
                object fieldValue = fieldType.ReadData(reader);

                // Save data to resulting script object
                string fieldName = null;
                if ((field != null) && (!String.IsNullOrEmpty(field.Name)))
                {
                    fieldName = field.Name;
                }
                else
                {
                    fieldName = DataObjectModel.GetStoredTypeName(fieldId);
                    if (fieldName == null)
                    {
                        fieldName = String.Format("field_{0:X8}", fieldId);
                    }
                }

                resultDict.Add(fieldName, fieldValue);
            }

            return result;
        }
    }
}
