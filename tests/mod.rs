#[cfg(test)]
mod tests {
    mod from_rust_crypto {
        use chacha20imp::chacha20::{ChaCha20, ChaCha20Impl};
        use hex_literal::hex;

        const KEY: [u8; 32] =
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        const IV: [u8; 12] = hex!("000000000000004a00000000");

        const PLAINTEXT: [u8; 114] = hex!(
            "
                4c616469657320616e642047656e746c
                656d656e206f662074686520636c6173
                73206f66202739393a20496620492063
                6f756c64206f6666657220796f75206f
                6e6c79206f6e652074697020666f7220
                746865206675747572652c2073756e73
                637265656e20776f756c642062652069
                742e
                "
        );

        const KEYSTREAM: [u8; 114] = hex!(
            "
                224f51f3401bd9e12fde276fb8631ded8c131f823d2c06
                e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b
                9334794cba40c63e34cdea212c4cf07d41b769a6749f3f
                630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53a
                c40c5945398b6eda1a832c89c167eacd901d7e2bf363
                "
        );

        const CIPHERTEXT: [u8; 114] = hex!(
            "
                6e2e359a2568f98041ba0728dd0d6981
                e97e7aec1d4360c20a27afccfd9fae0b
                f91b65c5524733ab8f593dabcd62b357
                1639d624e65152ab8f530c359f0861d8
                07ca0dbf500d6a6156a38e088a22b65e
                52bc514d16ccf806818ce91ab7793736
                5af90bbf74a35be6b40b8eedf2785e42
                874d
                "
        );

        #[test]
        fn chacha20_keystream() {
            let mut cipher = ChaCha20Impl::new(&KEY, &IV);

            // The test vectors omit the first 64-byte of the keystream
            let mut prefix = [0u8; 64];
            cipher.apply_keystream(&mut prefix);

            let mut buf = [0u8; 114];
            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &KEYSTREAM[..]);
        }

        #[test]
        fn chacha20_encryption() {
            let mut cipher = ChaCha20Impl::new(&KEY, &IV);
            let mut buf = PLAINTEXT;

            // The test vectors omit the first 64-bytes of the keystream
            let mut prefix = [0u8; 64];
            cipher.apply_keystream(&mut prefix);

            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &CIPHERTEXT[..]);
        }
    }

    mod keystream_tests {
        use chacha20imp::chacha20::{ChaCha20, ChaCha20Impl};
        use hex_literal::hex;

        #[test]
        fn chacha20_keystream_test_vector_0() {
            const KEY: [u8; 32] = hex!(
                "
                    000102030405060708090a0b0c0d0e0f
                    101112131415161718191a1b1c1d1e1f
                    "
            );

            const NONCE: [u8; 12] = hex!("000000090000004a00000000");

            let mut cipher = ChaCha20Impl::new(&KEY, &NONCE);
            cipher.seek(1);

            const KEYSTREAM: [u8; 64] = hex!(
                "
                    10f1e7e4d13b5915500fdd1fa32071c4
                    c7d1f4c733c068030422aa9ac3d46c4e
                    d2826446079faa0914c2d705d98b02a2
                    b5129cd1de164eb9cbd083e8a2503c4e
                    "
            );

            let mut buf: [u8; 64] = [0u8; 64];

            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &KEYSTREAM[..]);
        }

        #[test]
        fn chacha20_keystream_test_vector_1() {
            const KEY: [u8; 32] = hex!(
                "
                    00000000000000000000000000000000
                    00000000000000000000000000000000
                    "
            );

            const NONCE: [u8; 12] = hex!("000000000000000000000000");

            let mut cipher = ChaCha20Impl::new(&KEY, &NONCE);

            const KEYSTREAM: [u8; 64] = hex!(
                "
                    76b8e0ada0f13d90405d6ae55386bd28
                    bdd219b8a08ded1aa836efcc8b770dc7
                    da41597c5157488d7724e03fb8d84a37
                    6a43b8f41518a11cc387b669b2ee6586
                    "
            );

            let mut buf: [u8; 64] = [0u8; 64];

            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &KEYSTREAM[..]);
        }

        #[test]
        fn chacha20_keystream_test_vector_2() {
            const KEY: [u8; 32] = hex!(
                "
                    00000000000000000000000000000000
                    00000000000000000000000000000000
                    "
            );

            const NONCE: [u8; 12] = hex!("000000000000000000000000");

            let mut cipher = ChaCha20Impl::new(&KEY, &NONCE);
            cipher.seek(1);

            const KEYSTREAM: [u8; 64] = hex!(
                "
                    9f07e7be5551387a98ba977c732d080d
                    cb0f29a048e3656912c6533e32ee7aed
                    29b721769ce64e43d57133b074d839d5
                    31ed1f28510afb45ace10a1f4b794d6f
                    "
            );

            let mut buf: [u8; 64] = [0u8; 64];

            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &KEYSTREAM[..]);
        }

        #[test]
        fn chacha20_keystream_test_vector_3() {
            const KEY: [u8; 32] = hex!(
                "
                    00000000000000000000000000000000
                    00000000000000000000000000000001
                    "
            );

            const NONCE: [u8; 12] = hex!("000000000000000000000000");

            let mut cipher = ChaCha20Impl::new(&KEY, &NONCE);
            cipher.seek(1);

            const KEYSTREAM: [u8; 64] = hex!(
                "
                    3aeb5224ecf849929b9d828db1ced4dd
                    832025e8018b8160b82284f3c949aa5a
                    8eca00bbb4a73bdad192b5c42f73f2fd
                    4e273644c8b36125a64addeb006c13a0
                    "
            );

            let mut buf: [u8; 64] = [0u8; 64];

            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &KEYSTREAM[..]);
        }

        #[test]
        fn chacha20_keystream_test_vector_4() {
            const KEY: [u8; 32] = hex!(
                "
                    00ff0000000000000000000000000000
                    00000000000000000000000000000000
                    "
            );

            const NONCE: [u8; 12] = hex!("000000000000000000000000");

            let mut cipher = ChaCha20Impl::new(&KEY, &NONCE);
            cipher.seek(2);

            const KEYSTREAM: [u8; 64] = hex!(
                "
                    72d54dfbf12ec44b362692df94137f32
                    8fea8da73990265ec1bbbea1ae9af0ca
                    13b25aa26cb4a648cb9b9d1be65b2c09
                    24a66c54d545ec1b7374f4872e99f096
                    "
            );

            let mut buf: [u8; 64] = [0u8; 64];

            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &KEYSTREAM[..]);
        }

        #[test]
        fn chacha20_keystream_test_vector_5() {
            const KEY: [u8; 32] = hex!(
                "
                    00000000000000000000000000000000
                    00000000000000000000000000000000
                    "
            );

            const NONCE: [u8; 12] = hex!("000000000000000000000002");

            let mut cipher = ChaCha20Impl::new(&KEY, &NONCE);

            const KEYSTREAM: [u8; 64] = hex!(
                "
                    c2c64d378cd536374ae204b9ef933fcd
                    1a8b2288b3dfa49672ab765b54ee27c7
                    8a970e0e955c14f3a88e741b97c286f7
                    5f8fc299e8148362fa198a39531bed6d
                    "
            );

            let mut buf: [u8; 64] = [0u8; 64];

            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &KEYSTREAM[..]);
        }
    }

    mod chiper_tests {
        use chacha20imp::chacha20::{ChaCha20, ChaCha20Impl};
        use hex_literal::hex;

        #[test]
        fn cipher_test_vector_0() {
            const KEY: [u8; 32] = hex!(
                "
                    00000000000000000000000000000000
                    00000000000000000000000000000001
                    "
            );

            const NONCE: [u8; 12] = hex!(
                "
                    000000000000000000000002
                    "
            );

            const PLAINTEXT: [u8; 375] = hex!(
                "
                    416e79207375626d697373696f6e2074
                    6f20746865204945544620696e74656e
                    6465642062792074686520436f6e7472
                    696275746f7220666f72207075626c69
                    636174696f6e20617320616c6c206f72
                    2070617274206f6620616e2049455446
                    20496e7465726e65742d447261667420
                    6f722052464320616e6420616e792073
                    746174656d656e74206d616465207769
                    7468696e2074686520636f6e74657874
                    206f6620616e20494554462061637469
                    7669747920697320636f6e7369646572
                    656420616e20224945544620436f6e74
                    7269627574696f6e222e205375636820
                    73746174656d656e747320696e636c75
                    6465206f72616c2073746174656d656e
                    747320696e2049455446207365737369
                    6f6e732c2061732077656c6c20617320
                    7772697474656e20616e6420656c6563
                    74726f6e696320636f6d6d756e696361
                    74696f6e73206d61646520617420616e
                    792074696d65206f7220706c6163652c
                    20776869636820617265206164647265
                    7373656420746f
                    "
            );

            const CIPHERTEXT: [u8; 375] = hex!(
                "
                    a3fbf07df3fa2fde4f376ca23e827370
                    41605d9f4f4f57bd8cff2c1d4b7955ec
                    2a97948bd3722915c8f3d337f7d37005
                    0e9e96d647b7c39f56e031ca5eb6250d
                    4042e02785ececfa4b4bb5e8ead0440e
                    20b6e8db09d881a7c6132f420e527950
                    42bdfa7773d8a9051447b3291ce1411c
                    680465552aa6c405b7764d5e87bea85a
                    d00f8449ed8f72d0d662ab052691ca66
                    424bc86d2df80ea41f43abf937d3259d
                    c4b2d0dfb48a6c9139ddd7f76966e928
                    e635553ba76c5c879d7b35d49eb2e62b
                    0871cdac638939e25e8a1e0ef9d5280f
                    a8ca328b351c3c765989cbcf3daa8b6c
                    cc3aaf9f3979c92b3720fc88dc95ed84
                    a1be059c6499b9fda236e7e818b04b0b
                    c39c1e876b193bfe5569753f88128cc0
                    8aaa9b63d1a16f80ef2554d7189c411f
                    5869ca52c5b83fa36ff216b9c1d30062
                    bebcfd2dc5bce0911934fda79a86f6e6
                    98ced759c3ff9b6477338f3da4f9cd85
                    14ea9982ccafb341b2384dd902f3d1ab
                    7ac61dd29c6f21ba5b862f3730e37cfd
                    c4fd806c22f221
                    "
            );

            let mut buf = PLAINTEXT;
            let mut cipher = ChaCha20Impl::new(&KEY, &NONCE);
            cipher.seek(1);

            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &CIPHERTEXT[..]);
        }

        #[test]
        fn cipher_test_vector_1() {
            const KEY: [u8; 32] = hex!(
                "
                    1c9240a5eb55d38af333888604f6b5f0
                    473917c1402b80099dca5cbc207075c0
                    "
            );

            const NONCE: [u8; 12] = hex!(
                "
                    000000000000000000000002
                    "
            );

            const PLAINTEXT: [u8; 127] = hex!(
                "
                    2754776173206272696c6c69672c2061
                    6e642074686520736c6974687920746f
                    7665730a446964206779726520616e64
                    2067696d626c6520696e207468652077
                    6162653a0a416c6c206d696d73792077
                    6572652074686520626f726f676f7665
                    732c0a416e6420746865206d6f6d6520
                    7261746873206f757467726162652e
                    "
            );

            const CIPHERTEXT: [u8; 127] = hex!(
                "
                    62e6347f95ed87a45ffae7426f27a1df
                    5fb69110044c0d73118effa95b01e5cf
                    166d3df2d721caf9b21e5fb14c616871
                    fd84c54f9d65b283196c7fe4f60553eb
                    f39c6402c42234e32a356b3e764312a6
                    1a5532055716ead6962568f87d3f3f77
                    04c6a8d1bcd1bf4d50d6154b6da731b1
                    87b58dfd728afa36757a797ac188d1
                    "
            );

            let mut buf = PLAINTEXT;
            let mut cipher = ChaCha20Impl::new(&KEY, &NONCE);
            cipher.seek(42);

            cipher.apply_keystream(&mut buf);
            assert_eq!(&buf[..], &CIPHERTEXT[..]);
        }
    }
}
