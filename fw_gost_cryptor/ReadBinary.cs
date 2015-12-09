using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace fw_gost_cryptor
{
	class ReadBinary
	{
		public void ReadFile(string fileName)
		{
			FileStream fileStream = new FileStream(@fileName, FileMode.Open);
		}
	}
}
