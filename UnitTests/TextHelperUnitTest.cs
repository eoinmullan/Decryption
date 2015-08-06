using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Common;

namespace DecryptionUnitTests {
    [TestClass]
    public class TextHelperUnitTest {
        private TextHelper target;

        private string testText = "Fiddle tune, call the band, simple melancholy melody";

        [TestInitialize]
        public void Initialize() {
            target = new TextHelper();
        }

        [TestMethod]
        public void ShouldConfirmInputTextContainsGivenWords() {
            Assert.IsTrue(target.ContainsAll(testText, "tune"));
            Assert.IsTrue(target.ContainsAll(testText, "tune", "band"));
            Assert.IsTrue(target.ContainsAll(testText, "tune", "band", "simple"));
            Assert.IsTrue(target.ContainsAll(testText, "melody", "band", "Fiddle"));
        }

        [TestMethod]
        public void ShouldConfirmInputTextDoesNotContainWords() {
            Assert.IsFalse(target.ContainsAll(testText, "new"));
            Assert.IsFalse(target.ContainsAll(testText, "new", "day", "mist"));
        }
        
        [TestMethod]
        public void ShouldConfirmInputTextDoesNotContainAllWords() {
            Assert.IsFalse(target.ContainsAll(testText, "tune", "new"));
            Assert.IsFalse(target.ContainsAll(testText, "tune", "band", "mist", "simple"));
        }
    }
}
