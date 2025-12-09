using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace JitterChaChaRng
{
    // ---------- Platform-specific TSC reader ----------
    public static class TscReader
    {
        private static readonly bool _isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        // Try to load rdtsc.dll -> ReadTsc (stdcall returning unsigned long long)
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        private delegate ulong ReadTscNative();

        private static ReadTscNative _native = null;

        static TscReader()
        {
            if (_isWindows)
            {
                try
                {
                    // try to load rdtsc.dll from application dir (user-built)
                    IntPtr mod = LoadLibrary("rdtsc.dll");
                    if (mod != IntPtr.Zero)
                    {
                        IntPtr fn = GetProcAddress(mod, "ReadTsc");
                        if (fn != IntPtr.Zero)
                        {
                            _native = (ReadTscNative)Marshal.GetDelegateForFunctionPointer(fn, typeof(ReadTscNative));
                        }
                    }
                }
                catch
                {
                    _native = null;
                }
            }
        }

        // Returns a high-resolution timestamp: either RDTSC (if DLL available) or Stopwatch ticks fallback.
        public static ulong ReadTimestamp()
        {
            if (_native != null)
            {
                try
                {
                    return _native();
                }
                catch
                {
                    // fallback below
                }
            }

            // Normalize Stopwatch ticks into a 64-bit value that increases monotonically
            // Multiply to make it "larger" to approximate higher resolution when mixing bits.
            return (ulong)Stopwatch.GetTimestamp();
        }

        // Returns an estimated frequency when using Stopwatch fallback (ticks per second).
        public static double GetStopwatchFrequency()
        {
            return Stopwatch.Frequency;
        }

        public static bool IsUsingNativeTsc => _native != null;
    }

    // ---------- Simple ChaCha20 implementation (RFC 8439-ish, 20 rounds) ----------
    // This is a production-style (but not assembly-optimized) ChaCha20 block function.
    public sealed class ChaCha20
    {
        private readonly uint[] state = new uint[16]; // internal state
        private readonly byte[] key = new byte[32];
        private readonly byte[] nonce = new byte[12];
        private uint counter;

        public ChaCha20(byte[] keyBytes, byte[] nonceBytes, uint initialCounter = 1)
        {
            if (keyBytes == null || keyBytes.Length != 32) throw new ArgumentException("Key must be 32 bytes");
            if (nonceBytes == null || nonceBytes.Length != 12) throw new ArgumentException("Nonce must be 12 bytes");
            Buffer.BlockCopy(keyBytes, 0, key, 0, 32);
            Buffer.BlockCopy(nonceBytes, 0, nonce, 0, 12);
            counter = initialCounter;
        }

        private static uint Rotl(uint v, int c) => (v << c) | (v >> (32 - c));

        private void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = Rotl(d, 16);
            c += d; b ^= c; b = Rotl(b, 12);
            a += b; d ^= a; d = Rotl(d, 8);
            c += d; b ^= c; b = Rotl(b, 7);
        }

        private void BuildState(uint[] s, uint ctr)
        {
            // constants
            s[0] = 0x61707865; // "expa"
            s[1] = 0x3320646e; // "nd 3"
            s[2] = 0x79622d32; // "2-by"
            s[3] = 0x6b206574; // "te k"
            // key
            for (int i = 0; i < 8; i++) s[4 + i] = BitConverter.ToUInt32(key, i * 4);
            // counter
            s[12] = ctr;
            // nonce (12 bytes)
            s[13] = BitConverter.ToUInt32(nonce, 0);
            s[14] = BitConverter.ToUInt32(nonce, 4);
            s[15] = BitConverter.ToUInt32(nonce, 8);
        }

        // Produce one 64-byte keystream block
        private byte[] Block(uint ctr)
        {
            uint[] working = new uint[16];
            BuildState(working, ctr);
            uint[] x = new uint[16];
            Array.Copy(working, x, 16);

            for (int i = 0; i < 10; i++)
            {
                // column rounds
                QuarterRound(ref x[0], ref x[4], ref x[8], ref x[12]);
                QuarterRound(ref x[1], ref x[5], ref x[9], ref x[13]);
                QuarterRound(ref x[2], ref x[6], ref x[10], ref x[14]);
                QuarterRound(ref x[3], ref x[7], ref x[11], ref x[15]);
                // diagonal rounds
                QuarterRound(ref x[0], ref x[5], ref x[10], ref x[15]);
                QuarterRound(ref x[1], ref x[6], ref x[11], ref x[12]);
                QuarterRound(ref x[2], ref x[7], ref x[8], ref x[13]);
                QuarterRound(ref x[3], ref x[4], ref x[9], ref x[14]);
            }

            byte[] output = new byte[64];
            for (int i = 0; i < 16; i++)
            {
                uint v = x[i] + working[i];
                Array.Copy(BitConverter.GetBytes(v), 0, output, i * 4, 4);
            }
            return output;
        }

        // Fill a buffer with keystream bytes (advances counter)
        public void GetBytes(byte[] buffer)
        {
            int off = 0;
            while (off < buffer.Length)
            {
                var block = Block(counter++);
                int toCopy = Math.Min(64, buffer.Length - off);
                Array.Copy(block, 0, buffer, off, toCopy);
                off += toCopy;
            }
        }
    }

    // ---------- Entropy health monitor ----------
    public class EntropyHealthReport
    {
        public double LsbMean;           // average of LSBs (should be near 127.5 for uniform 0..255)
        public double LsbStdDev;
        public double SampleStdDev;      // stddev of raw delta values
        public double CollisionRate;     // fraction of repeated consecutive samples
        public int UniqueByteCount;      // unique byte values in recent window
        public string Warning;           // summary warning if any
        public DateTime Timestamp = DateTime.UtcNow;
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"[{Timestamp:O}] LSB mean={LsbMean:F2} stddev={LsbStdDev:F2}, sampleStdDev={SampleStdDev:F2}");
            sb.AppendLine($"UniqueBytes={UniqueByteCount}, CollisionRate={CollisionRate:P3}");
            if (!string.IsNullOrEmpty(Warning)) sb.AppendLine("WARNING: " + Warning);
            return sb.ToString();
        }
    }

    public class EntropyHealthMonitor
    {
        private readonly int _windowSize;
        private readonly Queue<byte> _samples;

        public EntropyHealthMonitor(int windowSize = 4096)
        {
            _windowSize = windowSize;
            _samples = new Queue<byte>(_windowSize);
        }

        // Feed raw bytes (LSB bytes from jitter samples)
        public void FeedBytes(byte[] buf)
        {
            foreach (var b in buf)
            {
                if (_samples.Count >= _windowSize) _samples.Dequeue();
                _samples.Enqueue(b);
            }
        }

        public EntropyHealthReport Analyze()
        {
            if (_samples.Count == 0) return new EntropyHealthReport { Warning = "No data" };

            var arr = _samples.ToArray();
            double mean = arr.Average(x => (double)x);
            double sd = Math.Sqrt(arr.Average(x => (x - mean) * (x - mean)));
            // collision rate: count consecutive identical bytes
            int collisions = 0;
            for (int i = 1; i < arr.Length; i++) if (arr[i] == arr[i - 1]) collisions++;
            double collisionRate = (double)collisions / Math.Max(1, arr.Length - 1);

            // unique count
            int unique = arr.Distinct().Count();

            // For sample stddev, interpret arr as unsigned bytes mapped to signed deltas around mean
            double sampleStd = sd;

            var report = new EntropyHealthReport
            {
                LsbMean = mean,
                LsbStdDev = sd,
                SampleStdDev = sampleStd,
                CollisionRate = collisionRate,
                UniqueByteCount = unique,
                Timestamp = DateTime.UtcNow
            };

            // Heuristics for warnings:
            var warnings = new List<string>();
            // mean should be near 127.5
            if (Math.Abs(mean - 127.5) > 10) warnings.Add($"LSB mean skewed by {mean - 127.5:F2}");
            if (sd < 20) warnings.Add($"LSB stddev low ({sd:F2})");
            if (collisionRate > 0.01) warnings.Add($"High consecutive-repeat rate {collisionRate:P2}");
            if (unique < 100) warnings.Add($"Low diversity: only {unique} unique bytes in window");

            report.Warning = warnings.Count > 0 ? string.Join("; ", warnings) : null;
            return report;
        }
    }

    // ---------- Jitter-based seeder and ChaCha20 generator ----------
    public sealed class JitterChaChaRng : IDisposable
    {
        private readonly object _lock = new object();
        private ChaCha20 _chacha;
        private byte[] _key = new byte[32];
        private byte[] _nonce = new byte[12];
        private long _generatedBytes = 0;
        private const long ReseedBytes = 1 << 20; // reseed after 1MB
        private readonly EntropyHealthMonitor _health;
        private readonly RandomNumberGenerator _osRng = RandomNumberGenerator.Create();

        public event Action<EntropyHealthReport> OnHealthReport;

        public JitterChaChaRng(int healthWindow = 4096)
        {
            _health = new EntropyHealthMonitor(healthWindow);
            Reseed(); // initial seed
        }

        public void GetBytes(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            lock (_lock)
            {
                if (_generatedBytes >= ReseedBytes) Reseed();
                _chacha.GetBytes(buffer);

                // defensive mix with OS RNG: XOR with OS bytes
                var os = new byte[buffer.Length];
                _osRng.GetBytes(os);
                for (int i = 0; i < buffer.Length; i++) buffer[i] ^= os[i];

                _generatedBytes += buffer.Length;
            }
        }

        public int NextInt32()
        {
            var b = new byte[4];
            GetBytes(b);
            return BitConverter.ToInt32(b, 0) & int.MaxValue;
        }

        private void Reseed()
        {
            // Gather jitter bytes
            var raw = GatherJitterBytes(8192); // gather many samples
            // Health monitoring
            _health.FeedBytes(raw);
            var report = _health.Analyze();
            OnHealthReport?.Invoke(report);
            // Hash + expand to get key + nonce
            var seed = ExpandWithSha256(raw, 48); // 32 key + 16 (we will use 12 nonce + 4 counter)
            // mix with OS RNG
            var os = new byte[seed.Length]; RandomNumberGenerator.Fill(os);
            for (int i = 0; i < seed.Length; i++) seed[i] ^= os[i];
            Array.Copy(seed, 0, _key, 0, 32);
            Array.Copy(seed, 32, _nonce, 0, 12);
            // set ChaCha with counter derived from last 4 bytes
            uint ctr = BitConverter.ToUInt32(seed, 32 + 12 - 4); // just some bytes as counter
            _chacha = new ChaCha20(_key, _nonce, ctr);
            _generatedBytes = 0;
            // zero sensitive temp data
            // (seed/raw will be eligible for GC; we won't zero them as these arrays are ephemeral)
        }

        // Gather jitter raw samples and return lower 8 bits per sample (LSB byte).
        private static byte[] GatherJitterBytes(int sampleCount)
        {
            var outBuf = new byte[sampleCount];
            // Prefer higher-res timestamp when available
            bool useTsc = TscReader.IsUsingNativeTsc;
            ulong last = TscReader.ReadTimestamp();
            for (int i = 0; i < sampleCount; i++)
            {
                // Busy work to create micro-variability
                Thread.SpinWait((i & 7) + 1);
                // small memory ops to hit caches
                uint tmp = unchecked((uint)i * 2654435761u);


                tmp ^= (tmp >> (i & 31));
                // read timestamp
                ulong now = TscReader.ReadTimestamp();
                ulong delta = (now >= last) ? (now - last) : (last - now);
                last = now;
                outBuf[i] = (byte)(delta & 0xFF);
            }
            return outBuf;
        }

        // Expand hashed input material to needed length using SHA256 counter mode
        private static byte[] ExpandWithSha256(byte[] input, int outLen)
        {
            using (var sha = SHA256.Create())
            {
                byte[] outBuf = new byte[outLen];
                int produced = 0;
                int counter = 0;
                while (produced < outLen)
                {
                    counter++;
                    var ctx = new byte[input.Length + 4];
                    Buffer.BlockCopy(input, 0, ctx, 0, input.Length);
                    ctx[ctx.Length - 4] = (byte)((counter >> 24) & 0xFF);
                    ctx[ctx.Length - 3] = (byte)((counter >> 16) & 0xFF);
                    ctx[ctx.Length - 2] = (byte)((counter >> 8) & 0xFF);
                    ctx[ctx.Length - 1] = (byte)(counter & 0xFF);
                    var h = sha.ComputeHash(ctx);
                    int toCopy = Math.Min(h.Length, outLen - produced);
                    Buffer.BlockCopy(h, 0, outBuf, produced, toCopy);
                    produced += toCopy;
                }
                return outBuf;
            }
        }

        public void Dispose()
        {
            _osRng?.Dispose();
            // zero key/nonce
            if (_key != null) Array.Clear(_key, 0, _key.Length);
            if (_nonce != null) Array.Clear(_nonce, 0, _nonce.Length);
        }
    }

    // ---------- Example usage and VS Code guidance ----------
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("JitterChaChaRng demo");
            Console.WriteLine($"Native RDTSC available: {TscReader.IsUsingNativeTsc}");
            if (!TscReader.IsUsingNativeTsc)
                Console.WriteLine($"Stopwatch.Frequency = {TscReader.GetStopwatchFrequency():N0} ticks/sec");

            using (var rng = new JitterChaChaRng())
            {
                rng.OnHealthReport += (r) =>
                {
                    Console.WriteLine(r.ToString());
                };

                // Produce a few random ints
                for (int i = 0; i < 16; i++)
                {
                    Console.WriteLine("Int: " + rng.NextInt32());
                }

                // Produce some random bytes
                var buf = new byte[64];
                rng.GetBytes(buf);
                Console.WriteLine("Bytes: " + BitConverter.ToString(buf));

                // Simulate long-running usage and periodic health checks
                for (int round = 0; round < 5; round++)
                {
                    Thread.Sleep(200); // simulate work
                    rng.GetBytes(buf);
                    Console.WriteLine($"Round {round}: {BitConverter.ToString(buf, 0, 8)}...");
                }
            }

            Console.WriteLine("Done.");
        }
    }
}
