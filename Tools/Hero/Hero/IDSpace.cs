using Hero.Types;
using System;
using System.Collections.Generic;

namespace Hero
{
  public class IDSpace
  {
    protected ulong start;
    protected ulong current;
    protected ulong end;
    protected Dictionary<ulong, HeroAnyValue> objects;

    public IDSpace(ulong Start, ulong End)
    {
      this.start = Start;
      this.end = End;
      this.current = Start;
      this.objects = new Dictionary<ulong, HeroAnyValue>();
    }

    public ulong Get()
    {
      if ((long) this.current == (long) this.end)
        throw new Exception("ID space exhausted");
      ulong num = this.current;
      ++this.current;
      return num;
    }

    public void Add(HeroAnyValue obj)
    {
      if (obj.ID < this.start || obj.ID >= this.end)
        throw new Exception("Object has a wrong ID for this space");
      this.objects[obj.ID] = obj;
    }
  }
}
