using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.Tables
{
    public static class ModificationNames
    {
        const long nameOffset = 0x647ac00000000;
        public static string GetName(long id)
        {
            StringTable st = StringTable.Find("str.itm.modifiers");
            return st.GetText(nameOffset + id, "whatever");
        }
    }
}
