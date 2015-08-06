using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Algorithms;

namespace DecryptionUnitTests {
    [TestClass]
    public class XORAlgorithmUnitTest {

        [TestMethod]
        public void ShouldConvertASCIICodesToUpperCaseCharactersWhenKeyIsNotSet() {
            var upperCaseASCIICodes = Enumerable.Range(65, 26);
            var upperCaseAlphabet = String.Concat(upperCaseASCIICodes.Select(x => (char)x));
            var commaSeperatedUpperCaseASCIICodes = string.Join(",", upperCaseASCIICodes);
            Assert.AreEqual(upperCaseAlphabet, Algorithms.XORDecryption(commaSeperatedUpperCaseASCIICodes));
        }

        [TestMethod]
        public void ShouldConvertASCIICodesToLowerCaseCharactersWhenKeyIsNotSet() {
            var lowerCaseASCIICodes = Enumerable.Range(97, 122);
            var lowerCaseAlphabet = String.Concat(lowerCaseASCIICodes.Select(x => (char)x));
            var commaSeperatedLowerCaseASCIICodes = string.Join(",", lowerCaseASCIICodes);
            Assert.AreEqual(lowerCaseAlphabet, Algorithms.XORDecryption(commaSeperatedLowerCaseASCIICodes));
        }

        [TestMethod]
        public void ShouldHandleEmptyString() {
            Assert.AreEqual("", Algorithms.XORDecryption(""));
        }

        [TestMethod]
        public void ShouldHandleNullString() {
            Assert.AreEqual("", Algorithms.XORDecryption(null));
        }

        [TestMethod]
        public void ShouldConvert65TokWhenKeyIs43() {
            Assert.AreEqual("jjjjj", Algorithms.XORDecryption("65,65,65,65,65", 43));
        }

        [TestMethod]
        public void ShouldConvert107ToAWhenKeyIs43() {
            Assert.AreEqual("AAAAA", Algorithms.XORDecryption("106,106,106,106,106", 43));
        }

        [TestMethod]
        public void ShouldRepeatKeyCyclicallyThroughoutMessage() {
            Assert.AreEqual("Secret Message", Algorithms.XORDecryption("68,69,73,186,190,99,0,103,173,168,100,65,77,173", 23, 32, 42, 200, 219));
        }

        [TestMethod]
        public void ShouldReturnErrorMessageWhenInputTextIsNotWellFormed() {
            Assert.AreEqual(Decryption.Properties.Resources.InvalidInput, Algorithms.XORDecryption("Non ASCII code message", 42, 43, 44));
            Assert.AreEqual(Decryption.Properties.Resources.InvalidInput, Algorithms.XORDecryption("107,a107,107,107,107", 42, 43, 44));
        }
    }
}
