using System;
using System.IO;
using OpenSslAes;

namespace OpenSslAes
{
	class MainClass
	{
		public static void Main (string[] args)
		{
			
			FileStream fsInput = new FileStream(args[1], FileMode.Open, FileAccess.Read);
			FileStream fsOutput = new FileStream(args[2], FileMode.Create, FileAccess.Write);
			
			if (args [0] == "enc") {
				OpenSslAes.Encrypt(fsInput, fsOutput, args[3]);
			} else if (args [0] == "dec") {
				OpenSslAes.Decrypt(fsInput, fsOutput, args[3]);
			}
		}
	}
}
