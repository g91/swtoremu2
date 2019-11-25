using System;
using System.Globalization;

namespace SWTORParser.Hero.Types
{
    public class HeroVector3 : HeroAnyValue
    {
        public float x;
        public float y;
        public float z;

        public HeroVector3(float x = 0.0f, float y = 0.0f, float z = 0.0f)
        {
            Type = new HeroType(HeroTypes.Vector3);
            this.x = x;
            this.y = y;
            this.z = z;
        }

        public override string ValueText
        {
            get { return string.Format("({0}, {1}, {2})", x, y, z); }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            stream.Read(out x);
            stream.Read(out y);
            stream.Read(out z);
        }

        public override void Serialize(PackedStream2 stream)
        {
            stream.Write(x);
            stream.Write(y);
            stream.Write(z);
        }

        public override void Unmarshal(string data, bool withV = true)
        {
            if (withV)
            {
                Unmarshal(GetRoot(data).InnerXml, false);
            }
            else
            {
                string str = data;
                str.Trim();
                string[] strArray = str.Substring(1, str.Length - 2).Split(new char[1]
                                                                               {
                                                                                   ','
                                                                               });
                x = Convert.ToSingle(strArray[0], CultureInfo.InvariantCulture);
                y = Convert.ToSingle(strArray[1], CultureInfo.InvariantCulture);
                z = Convert.ToSingle(strArray[2], CultureInfo.InvariantCulture);
                hasValue = true;
            }
        }
    }
}