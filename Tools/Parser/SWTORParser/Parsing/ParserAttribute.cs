using System;

namespace SWTORParser.Parsing
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
    public sealed class ParserAttribute : Attribute
    {
        public ParserAttribute(Opcode opcode)
        {
            Opcode = opcode;
        }

        /*public ParserAttribute(Opcode opcode, ClientVersionBuild addedInVersion)
        {
            if (ClientVersion.AddedInVersion(addedInVersion))
                Opcode = Opcode.GetOpcode(opcode);
        }

        public ParserAttribute(Opcode opcode, ClientVersionBuild addedInVersion, ClientVersionBuild removedInVersion)
        {
            if (ClientVersion.AddedInVersion(addedInVersion) && ClientVersion.RemovedInVersion(removedInVersion))
                Opcode = Opcode.GetOpcode(opcode);
        }

        public ParserAttribute(int opcode)
        {
            Opcode = opcode;
        }*/

        public Opcode Opcode { get; private set; }
    }
}
