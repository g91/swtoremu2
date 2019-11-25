using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.ModelLoader
{
    class QuestStepLoader
    {
        public string ClassName
        {
            get { return "qstStepDefinition"; }
        }

        public static QuestStep Load(GomObjectData obj, QuestBranch branch)
        {
            QuestStep step = new QuestStep();

            step.Id = (int)obj.ValueOrDefault<long>("qstStepId", 0);
            step.Branch = branch;
            step.IsShareable = obj.ValueOrDefault<bool>("qstStepIsShareable", false);

            step.Tasks = new List<QuestTask>();
            var tasks = (List<object>)obj.ValueOrDefault<List<object>>("qstTasks", null);
            if (tasks != null)
            {
                foreach (var taskDef in tasks)
                {
                    var tsk = QuestTaskLoader.Load((GomObjectData)taskDef, step);
                    step.Tasks.Add(tsk);
                }
            }

            var stringIds = (List<object>)obj.ValueOrDefault<List<object>>("qstStepJournalEntryStringIdList", null);
            var strings = new List<string>();
            if (stringIds != null)
            {
                var txtLookup = branch.Quest.TextLookup;
                foreach (var strId in stringIds)
                {
                    long key = (long)(ulong)strId;
                    if (txtLookup.ContainsKey(key))
                    {
                        strings.Add(StringTable.TryGetString(branch.Quest.Fqn, (GomObjectData)txtLookup[key]));
                    }
                    else
                    {
                        strings.Add(String.Empty);
                    }
                }
            }

            step.JournalText = String.Join("\n\n", strings.ToArray());

            return step;
        }
    }
}
