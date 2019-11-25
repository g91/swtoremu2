using System;

namespace SWTORParser.Hero
{
    public class SerializingException : Exception
    {
        public SerializingException(string message)
            : base(message)
        {
        }
    }
}