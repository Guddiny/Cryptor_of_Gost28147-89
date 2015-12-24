using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace fw_gost_cryptor
{
	class XmlFileCommander:FileCommander
	{
		XmlDocument xmlDoc = new XmlDocument();

		public  byte[] ReadXml(string FileName, string Atribute)
		{
			List<byte> tempResult = new	List<byte>();
			xmlDoc.Load(FileName);
			XmlNode rootNode = xmlDoc.DocumentElement;
			XmlTextReader xmlReader = new XmlTextReader(FileName);
			while (xmlReader.Read())
			{
				if (xmlReader.Name == "firmware")
				{
					string s = xmlReader.GetAttribute(Atribute);
					for (int i = 0; i < s.Length / 2; i++)
					{
						if (i * 2 + 1 < s.Length)
						{
							string s2 = Convert.ToString(s[i * 2]);
							string s3 = Convert.ToString(s[i * 2 + 1]);
							string s4 = s2 + s3;

							int a = int.Parse(s4, System.Globalization.NumberStyles.HexNumber);
							tempResult.Add(Convert.ToByte(a));
						}
					}
				}
			}
			byte[] result = tempResult.ToArray();
			return result;
		}

		public void WriteXml(byte[] data, string fileName) 
		{
			StringBuilder MyStringBuilder = new StringBuilder();
			XmlTextWriter xmlWriter = new XmlTextWriter(fileName, Encoding.UTF8);

			foreach (Byte bz in data)
			{
				int a = (int)bz;
				MyStringBuilder.Append(a.ToString("X2"));
			}

			xmlWriter.WriteStartElement("project");
				xmlWriter.WriteStartElement("firmware");
					xmlWriter.WriteAttributeString("data", Convert.ToString(MyStringBuilder));
					xmlWriter.WriteAttributeString("version", "1.12");
				xmlWriter.WriteEndElement();
			xmlWriter.WriteEndElement();
			xmlWriter.Close();
		}
	}
}
