using Hero;
using System;
using System.Globalization;

namespace Hero.Types
{
  public class HeroVector3 : HeroAnyValue
  {
    public float x;
    public float y;
    public float z;

    public override string ValueText
    {
      get
      {
        return string.Format("({0}, {1}, {2})", (object) this.x, (object) this.y, (object) this.z);
      }
    }

    public HeroVector3(float x = 0.0f, float y = 0.0f, float z = 0.0f)
    {
      this.Type = new HeroType(HeroTypes.Vector3);
      this.x = x;
      this.y = y;
      this.z = z;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      stream.Read(out this.x);
      stream.Read(out this.y);
      stream.Read(out this.z);
    }

    public override void Serialize(PackedStream_2 stream)
    {
      stream.Write(this.x);
      stream.Write(this.y);
      stream.Write(this.z);
    }

    public override void Unmarshal(string data, bool withV = true)
    {
      if (withV)
      {
        this.Unmarshal(this.GetRoot(data).InnerXml, false);
      }
      else
      {
        string str = data;
        str.Trim();
        string[] strArray = str.Substring(1, str.Length - 2).Split(new char[1]
        {
          ','
        });
        this.x = Convert.ToSingle(strArray[0], (IFormatProvider) CultureInfo.InvariantCulture);
        this.y = Convert.ToSingle(strArray[1], (IFormatProvider) CultureInfo.InvariantCulture);
        this.z = Convert.ToSingle(strArray[2], (IFormatProvider) CultureInfo.InvariantCulture);
        this.hasValue = true;
      }
    }
  }
}
