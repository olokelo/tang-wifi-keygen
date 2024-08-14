# Tang Wi-Fi Key Generator

A C program generating JWK keys for [Tang](https://github.com/latchset/tang) network presence server based on nearby Wi-Fi network SSIDs and MAC addresses. It uses OpenSSL and jose and is best suited to be ran on OpenWrt routers.

# Motivation

The goal of this project is to make disks undecryptable unless you're in specific environment (physical location).
Ever since I started using Tang in my homelab I always wondered if there's a way not to store the key anywhere so it can't be recovered even if some malicious entity manages to steal key parts of the infrastructure. Tang promised BLE beacons and other cool radio based stuff for unlocking but it seems like it never really took off.

Not all devices support TPM and even when they do, there have been [documented vulnerabilities](https://www.cve.org/CVERecord?id=CVE-2024-0762) present in the wild. Currently most home routers capable of running OpenWrt anyways so the only way of running Tang service on them is to generate and store the key on the unencrypted flash.

However this project is **by no means safe** to use. I wrote the code in my free time and I'm not an expert on cryptography. There are **major security risks** you have to consider using this project. I described them in later paragraph.

# How does it work

## First approach

The naive approach would be to just check if all user-coded networks are present near the device and based on that information either start Tang or not. This however is prone to key extraction attacks.

## Second approach

The second logical step would be to derive key from detected SSID and MAC addresses of visible Wi-Fi devices. This can be done using hashing algorithms with `HMAC`. Due to inherent nature of wireless communication and possibly other factors we can't reliably assume all networks will be visible at all time. Sometimes a wireless network might go down due to power or device failure, other times the signal might be suppressed by another wireless device operating at the same frequency. Additionally the program wouldn't have a way of knowing which networks to use in hashing process and in what order.

## Current approach

The third approach is the one actually used as of the first version of Tang Key Generator. Wi-Fi networks form a `hashplane` which is then used as an input to `PBKDF2-HMAC` function which hashes plane many times, with salt and `HMAC`. It shares similarities with how passwords are treated. You can think of `hashplane` as fairly lengthy password created from Wi-Fi networks around the device.

There comes the issue how do we know if the Wi-Fi network detected was a part of original `hashplane`. To overcome this we create a second plane referred to as `controlplane` which contains very short checksums of each network forming a `hashplane` in the correct order. `controlplane` **needs** to be preserved across server reboots. The checksums in `controlplane` are intentionally insecure to produce a lot of collisions yet still be somewhat reliable to decide if we should use this network in `hashplane`. If the attacker gained access to the `controlplane` saved in `metafile` on the disk, it should be impossible to "reverse" those checksums and get clear input. Currently the preferred length of such checksum is `3 bytes` == `24 bits`. Assuming that one Wi-Fi network gives us around `64 bits` of entropy (`~40 bits` MAC + `~24 bits` SSID), each checksum should have around `2**40` collisions. If we used 6 networks to form the planes, the attacker would have `(2**40)**5` inputs to brute-force (`~200 bits` strength). Note that this part is purely theoretical and in fact depending on hash length used in `hashplane` (`12 bytes` by default), collisions on that hash would probably also occur.

Next problem is that we can't expect to have all Wi-Fi networks forming `hashplane` available at all times yet we still need to reconstruct the `hashplane` and derive `key` from it. There are many approaches to this issue possibly involving [fuzzy hashing](https://en.wikipedia.org/wiki/Fuzzy_hashing) or even some form of [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) which the original Tang uses, however it's crucial to recreate entire `hashplane` to get the key and not just determine how similar it is to the original one. After considering the options, none of them made much sense for this specific use-case. The simplest and best (for now) approach is to use Reed-Solomon which allows to recreate lost parts of the `hashplane`. Keep in mind, Reed-Solomon recovery data is also stored in `metafile` unencrypted so it's wise not to include too much of it.

Here's how much `key` entropy we get after allowing up to `r` networks to be lost assuming default configuration (`96 bit` hash, `512 bit` key)
| `r` networks lost | `key` entropy | safe        |
|:-----------------:|:-------------:|:-----------:|
| 0                 | 512 bits      | yes         |
| 1                 | 416 bits      | yes         |
| 2                 | 320 bits      | yes         |
| 3                 | 224 bits      | depends     |
| 4                 | 128 bits      | not really  |
| 5                 | 32 bits       | **no**      |
| 5+                | 0 bits*       | **no!**     |

*It is reasonable to assume, when attacker has more `hashplane recovery` data than the resulting `key` hash length it's probably not hard to recover the entire `key` although I don't know how it can be done in practice.

Lastly, we need to generate two ES521 P-521 private keys that Tang normally uses (one for key exchange and one ECMR). The highest hash length we can use in `PBKDF2` is `512 bits` (SHA-512) so we expand the `key` with SHAKE-256 and use the expansion to create two `521 bit` private keys.

# How to use

## Linux

Tang Wi-Fi Key Generator (twkg) can be run as a standalone program.

Requirements:
- gcc / clang
- make
- openssl 3
- jose
- jansson
- wolfssl (optionally)

Clone repo and build twkg:

```shell
git clone --recurse-submodules https://github.com/olokelo/tang-wifi-keygen.git
cd tang-wifi-keygen
make
```

First of all create `metafile` which contains parameters, salts, `controlplane` and `recovery` data.
You'll need a `wifi.json` in a format that `ubus call iwinfo scan '{"device":"wifi_dev"}'` gives. You can either generate it yourself or grab from `tests/` directory.

The number of networks found in this file sets the `n` parameter. The `p` parameter determines how many networks need to be present to reconstruct the key. The `r` parameter is calculated automatically from `r = n - p` and means how many networks can be lost (take look at the table above).

Assuming `p = 5` and you have at least 5 networks in `wifi.json`
```shell
./twkg gen metafile.bin 5 < wifi.json
```

Now to recreate the key and put `.jwk` files in `/tmp` use:
```shell
./twkg rec metafile.bin /tmp/ < wifi.json
```
You can play around with the `p` parameter and modify `wifi.json` to see if the program is able to recover lost networks.

## OpenWRT

### Build

It's possible to install twkg from an `.ipk` file built for specific OpenWRT system. The `packages/` directory contains a feed used to build the package with the OpenWRT toolchain. More information about building packages can be found [here](https://openwrt.org/docs/guide-developer/helloworld/chapter1).

After cloning OpenWRT repo, installing the toolchain, updating the feeds and setting the target, the package can be built with the following commands:

```shell
cd <path_to_openwrt>
echo "src-link twkg <path_to_twkg>/packages" > feeds.conf
./scripts/feeds update twkg
./scripts/feeds install -a -p twkg
make menuconfig  # enable twkg package in Utilities submenu
make V=sc package/twkg/clean
make V=sc package/twkg/compile
```

If there were no build errors, the resulting `.ipk` file will be in `bin/packages/mipsel_24kc/twkg/`.

### Install and configure

On the OpenWRT device, you first need to install `tang` package. Do not start the `tang` service and disable it on startup. `twkg` will automatically start tang after successful `key` reconstruction.

```shell
opkg install tang
service tang disable
```

Now you can transfer `.ipk` file built in the previous step and install it on OpenWRT device.

```shell
opkg install /tmp/twkg_*.ipk
```

To create `metafile`, you'll need a file containing Wi-Fi networks in `json` format.
Assuming your wireless device is `phy0-sta0`, it can be generated it with:

```shell
ubus call iwinfo scan '{"device":"phy0-sta0"}' > /tmp/wifi.json
```

Review and modify the `/tmp/wifi.json` file to only include networks that will form `hiddenplane`. Then you can generate `metafile`. Here the `p` parameter is set to `5`.

```
twkg gen /usr/share/twkg/metafile.bin 5 < /tmp/wifi.json
```

Now configure twkg service setting the device and enable `twkg` service to start on boot.

```shell
uci set twkg.config.device=phy0-sta0
uci set twkg.config.enabled=1
service twkg start
service twkg enable
```

You can verify the key was reconstructed correctly in the logs:
```
Wed Aug 14 10:12:37 2024 daemon.err twkg_then_tang[1690]: twkg reconstruction succeeded
Wed Aug 14 10:12:37 2024 daemon.err twkg_then_tang[1690]: Listening on 0.0.0.0:9090
Wed Aug 14 10:12:37 2024 daemon.err twkg_then_tang[1690]: Listening on [::]:9090
```

If you see similar output, this means key was recreated and `tang` was started. From now on, you can do key exchange as usual.

# Security risks

There are several major concerns when it comes to security of Tang Keygen

- The P-521 curves do not use their full entropy (only up to `512 bits` combined) as mentioned above.
- It *might* be possible to somehow combine the `controlplane` and `recovery` data to further reduce the missing entropy.
- Knowledgeable attacker could try to make snapshot of Wi-Fi networks in the infrastructures environment. It would then not be all that hard to recreate the key. It's **strongly recommend** to also use proper Tang server binded to TPM as a part of SSS.
- It would be wise not to use common SSIDs like `Hotspot`, `ASUS` or `Home` as it would greatly reduce the entropy of that `hashplane` part.

# Testing

To run tests you need to have [criterion](https://github.com/Snaipe/Criterion) installed. Tests can be ran with:

```shell
make tests
./twkg_test --verbose=info -j1
```
