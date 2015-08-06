using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Models;
using DecryptionFs;

namespace DecryptionUnitTests {
    [TestClass]
    public class CaesarShiftAlgorithmUnitTest {

        [TestMethod]
        public void ShouldHandleEmptyStringInput() {
            Assert.AreEqual("", AlgorithmsFs.CaesarShiftDecryption("", 0));
        }

        [TestMethod]
        public void ShouldHandleNullStringInput() {
            Assert.AreEqual("", AlgorithmsFs.CaesarShiftDecryption(null, 0));
        }

        [TestMethod]
        public void ShouldReturnEncryptedTextUnchangedWhenZeroKeyIsUsed() {
            var testSentence = "The Quick Brown Fox Jumped Over The Lazy Dog.";

            Assert.AreEqual(testSentence, AlgorithmsFs.CaesarShiftDecryption(testSentence, 0));
        }

        [TestMethod]
        public void ShouldShiftBy16CharactersWordsRespectingCase() {
            var encryptedSentence = "AesMu LbYgx PyH TeWZc yFob dro VkJI Nyq";
            var expectedDecryptedSentence = "QuiCk BrOwn FoX JuMPs oVer the LaZY Dog";

            Assert.AreEqual(expectedDecryptedSentence, AlgorithmsFs.CaesarShiftDecryption(encryptedSentence, 16));
        }

        [TestMethod]
        public void ShouldShiftMessageWhileLeavingPuntuationIntact() {
            var encryptedSentence = "Aes.Mu L?bYgx P<yH> Te(WZc) yFob! d££ro V;k:JI N]y[q";
            var expectedDecryptedSentence = "Qui.Ck B?rOwn F<oX> Ju(MPs) oVer! t££he L;a:ZY D]o[g";

            Assert.AreEqual(expectedDecryptedSentence, AlgorithmsFs.CaesarShiftDecryption(encryptedSentence, 16));
        }

        [TestMethod]
        public void ShouldUseKeySuppliedInConstructor() {
            var encryptedSentence = "AesMu LbYgx PyH TeWZc yFob dro VkJI Nyq";
            var expectedDecryptedSentence = "QuiCk BrOwn FoX JuMPs oVer the LaZY Dog";

            Assert.AreEqual(expectedDecryptedSentence, AlgorithmsFs.CaesarShiftDecryption(encryptedSentence, 16));
        }
    }
}
