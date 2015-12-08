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
			uint[] key = { 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888 };
			uint[] plain = { 0xAAAAAAAA, 0xBBBBBBBB };
			uint[] cipher = new uint[2];
			uint[] result = new uint[2];
			int position = 0;

			FileStream fileStream = new FileStream(@"usb_hid_64_11.bin", FileMode.Open);
			BinaryReader binReader = new BinaryReader(fileStream);
			Gost28147_89 gost28147_89 = new Gost28147_89();
			int lenght = (int)fileStream.Length;

			gost28147_89.kboxinit();

			byte[] dataByte = binReader.ReadBytes(lenght);



			/*Console.WriteLine("{0:x2} ", plain[0]);
			gost28147_89.gostcrypt(plain, cipher, key);
			Console.WriteLine("{0:x2} ", cipher[0]);
			gost28147_89.gostdecrypt(cipher, result, key);
			Console.WriteLine("{0:x2} ",result[0]);*/

			Console.WriteLine(lenght);
			Console.ReadKey();
		}
	}
}
