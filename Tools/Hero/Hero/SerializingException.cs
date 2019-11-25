using System;

namespace Hero
{
  public class SerializingException : Exception
  {
    public SerializingException(string message)
      : base(message)
    {
    }
  }
}
