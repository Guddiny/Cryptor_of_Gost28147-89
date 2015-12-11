using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace fw_gost_cryptor
{
	class Program
	{
		static void Main(string[] args)
		{
			Console.BackgroundColor = ConsoleColor.DarkBlue;
			Console.Clear();

			FileCommander fileCommander = new FileCommander();
			Gost28147_89 gost28147_89 = new Gost28147_89();
			
			gost28147_89.kboxinit();
			gost28147_89.ReadKey();

			byte[] inputData = fileCommander.ReadFile("usb_hid_64_11.bin");

			byte[] outputData = gost28147_89.gostDataCrypt(inputData);

			byte[] reoutputData = gost28147_89.gostDataDecrypt(outputData);


			Console.WriteLine("File size is: {0} bytes", fileCommander.FileSize);
			Console.ReadKey();
		}
	}
}
