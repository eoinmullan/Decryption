using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Models;

namespace DecryptionUnitTests {
    [TestClass]
    public class ObservableTextUnitTest {
        ObservableText target;

        [TestInitialize]
        public void Initialize() {
            target = new ObservableText();
        }

        [TestMethod]
        public void ShouldSetAndGetText() {
            target.Text = "Some test text";

            Assert.AreEqual("Some test text", target.Text);
        }
    }
}
