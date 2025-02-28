import unittest
import hmac
import hashlib
import binascii

class TestSPAKE2Vectors(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_vectors = {
            "context": b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors",
            "idProver": b"client",
            "idVerifier": b"server",
            "w0": binascii.unhexlify("bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"),
            "w1": binascii.unhexlify("7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"),
            "L": binascii.unhexlify("04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd"),
            "x": binascii.unhexlify("d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539"),
            "shareP": binascii.unhexlify("04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb17330090" +
                                         "42c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e3" +
                                         "41727"),
            "y": binascii.unhexlify("717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3"),
            "shareV": binascii.unhexlify("04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcad" +
                                         "ea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a6843" +
                                         "7b048"),
            "Z": binascii.unhexlify("04bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d5" +
                                     "0091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c41839"),
            "V": binascii.unhexlify("0458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8" +
                                     "b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b68"),
            "TT": binascii.unhexlify("38000000000000005350414b45322b2d503235362d5348413235362d484b4" +
                                      "4462d5348413235362d484d41432d534841323536205465737420566563746f72730" +
                                      "600000000000000636c69656e7406000000000000007365727665724100000000000" +
                                      "00004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12" +
                                      "f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20410" +
                                      "000000000000004d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f9" +
                                      "8baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e6" +
                                      "56edbe7410000000000000004ef3bd051bf78a2234ec0df197f7828060fe98565035" +
                                      "79bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab" +
                                      "97a79c7193e341727410000000000000004c0f65da0d11927bdf5d560c69e1d7d939" +
                                      "a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e0" +
                                      "9986ab46742c798a9a68437b048410000000000000004bbfce7dd7f277819c8da215" +
                                      "44afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e" +
                                      "67e2ca633117a4fbd559946ab474356c4183941000000000000000458bf27c6bca01" +
                                      "1c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e66" +
                                      "4f23db7c01edc87faa530db01c2ee405230b18997f16b682000000000000000bb8e1" +
                                      "bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"),
            "K_main": binascii.unhexlify("4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29"),
            "K_confirmP": binascii.unhexlify("871ae3f7b78445e34438fb284504240239031c39d80ac23eb5ab9be5ad6db58a"),
            "K_confirmV": binascii.unhexlify("ccd53c7c1fa37b64a462b40db8be101cedcf838950162902054e644b400f1680"),
            "HMAC_P": binascii.unhexlify("926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527"),
            "HMAC_V": binascii.unhexlify("9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68"),
            "K_shared": binascii.unhexlify("0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7")
        }
        cls.M_UNCOMPRESSED = binascii.unhexlify(
            "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20"
        )
        cls.N_UNCOMPRESSED = binascii.unhexlify(
            "04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7"
        )

    def calculate_hmac_sha256(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def test_prover_calculations(self):
        """Verify prover (client) calculations against test vectors."""
        tv = self.test_vectors

        # 1. Verify w0 is derived correctly (32 bytes)
        self.assertEqual(len(tv["w0"]), 32, "w0 should be 32 bytes long")

        # 2. Verify shareP calculation (uncompressed format check)
        self.assertEqual(tv["shareP"][0], 0x04,
                         "shareP should start with 0x04 (uncompressed format)")

        # 3. Verify Z calculation (uncompressed format check)
        self.assertEqual(tv["Z"][0], 0x04,
                         "Z should start with 0x04 (uncompressed format)")

        # 4. Verify transcript hash TT is non-empty
        self.assertTrue(len(tv["TT"]) > 0, "Transcript hash TT should not be empty")

        # 5. Verify key derivation: K_main, K_confirmP, and K_shared (32 bytes each)
        self.assertEqual(len(tv["K_main"]), 32, "K_main should be 32 bytes long")
        self.assertEqual(len(tv["K_confirmP"]), 32, "K_confirmP should be 32 bytes long")
        self.assertEqual(len(tv["K_shared"]), 32, "K_shared should be 32 bytes long")

        # 6. Verify HMAC calculation: HMAC_P should equal HMAC(K_confirmP, shareV)
        calculated_hmac_p = self.calculate_hmac_sha256(tv["K_confirmP"], tv["shareV"])
        self.assertEqual(calculated_hmac_p, tv["HMAC_P"],
                         "Calculated HMAC_P does not match the expected value")

    def test_verifier_calculations(self):
        """Verify verifier (server) calculations against test vectors."""
        tv = self.test_vectors

        # 1. Verify y (server private key) is 32 bytes long
        self.assertEqual(len(tv["y"]), 32, "y should be 32 bytes long")

        # 2. Verify shareV calculation (uncompressed format check)
        self.assertEqual(tv["shareV"][0], 0x04,
                         "shareV should start with 0x04 (uncompressed format)")

        # 3. Verify key derivation: K_confirmV (32 bytes)
        self.assertEqual(len(tv["K_confirmV"]), 32, "K_confirmV should be 32 bytes long")

        # 4. Verify HMAC calculation: HMAC_V should equal HMAC(K_confirmV, shareP)
        calculated_hmac_v = self.calculate_hmac_sha256(tv["K_confirmV"], tv["shareP"])
        self.assertEqual(calculated_hmac_v, tv["HMAC_V"],
                         "Calculated HMAC_V does not match the expected value")

if __name__ == "__main__":
    unittest.main()
