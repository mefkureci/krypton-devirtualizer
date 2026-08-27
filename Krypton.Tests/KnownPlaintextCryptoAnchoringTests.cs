using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Krypton.Core.Architecture;
using Krypton.Pipeline.Stages;
using Xunit;

namespace Krypton.Tests
{
    public sealed class KnownPlaintextCryptoAnchoringTests
    {
        [Fact]
        public void Evaluate_UsesUncheckedInt32SemanticsAtOverflowSites()
        {
            Assert.Equal(
                -1897169053,
                KnownPlaintextCryptoAnchoring.Evaluate(VMOpCode.Sub, 529241092, -1868557151));
            Assert.Equal(
                1524436267,
                KnownPlaintextCryptoAnchoring.Evaluate(VMOpCode.Add, -1006765862, -1763765167));
        }

        [Fact]
        public void CSharpDecrypt_MatchesResearchReference_WhenSampleArtifactIsAvailable()
        {
            var root = FindRepositoryRoot();
            var path = Path.Combine(root, "work", "resdump", "ErrorParameter.bin");
            if (!File.Exists(path))
                return;

            var key = Convert.FromHexString(
                "9e93978ca54f63fa768755943b8927697b1e6a2fe8742471b8cd4e424d2d0e60");
            var iv = Convert.FromHexString("8f843b47eb771da5a94f8f101df2436d");
            var plaintext = KnownPlaintextCryptoAnchoring.Decrypt(File.ReadAllBytes(path), key, iv);

            Assert.NotNull(plaintext);
            Assert.True(KnownPlaintextCryptoAnchoring.IsRsaXml(plaintext));
            Assert.Equal(
                "ad71c6541bccbc367308fc8334c6ef94237c17d3fc491c6541be674b33b6d1aa",
                Convert.ToHexString(SHA256.HashData(plaintext)).ToLowerInvariant());
        }

        private static string FindRepositoryRoot()
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory != null)
            {
                if (directory.EnumerateFiles("Krypton.sln").Any())
                    return directory.FullName;
                directory = directory.Parent;
            }
            throw new DirectoryNotFoundException("Krypton.sln not found.");
        }
    }
}
