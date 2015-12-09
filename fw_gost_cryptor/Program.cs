using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace fw_gost_cryptor
{
	class Program
	{
		static void Main(string[] args)
		{
			
			uint[] plain = { 0xAAAAAAAA, 0xBBBBBBBB };
			uint[] cipher = new uint[2];
			uint[] result = new uint[2];
			int position = 0;

			ReadBinary readBinary = new ReadBinary();
			readBinary.ReadFile("usb_hid_64_11.bin");
			Gost28147_89 gost28147_89 = new Gost28147_89();


			gost28147_89.kboxinit();
			gost28147_89.ReadKey();

			Console.WriteLine("{0:x2} ", plain[0]);
			gost28147_89.gostcrypt(plain, cipher, gost28147_89.Key);
			Console.WriteLine("{0:x2} ", cipher[0]);
			gost28147_89.gostdecrypt(cipher, result, gost28147_89.Key);
			Console.WriteLine("{0:x2} ",result[0]);

			Console.ReadKey();
		}
	}
}
