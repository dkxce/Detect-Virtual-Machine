//
// C#
// IS_VIRT_CS
// v 0.2, 16.11.2023
// https://github.com/dkxce/Detect-Virtual-Machine
// en,ru,1251,utf-8
//


using System;

namespace IS_VIRT_CS
{
    internal class Program
    {
        static int Main(string[] args)
        {
            bool isVirt = Virtualization.IsVirtualMachine();
            if (isVirt) Console.WriteLine("9 YES, Machine is Virtual");
            else Console.WriteLine("0 NO, Machine is Phisical");
            if (isVirt) return 9;
            else return 0;
        }
    }
}
